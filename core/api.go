package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/crowdsec"
)

// APIServer serves management, metrics, and SSE event streaming over TCP and/or Unix sockets.
type APIServer struct {
	cfg       *config.Config
	banlist   *BanList
	stats     *StatsRegistry
	bus       *EventBus
	crowdsec  *crowdsec.Client
	srv       *http.Server
	listeners []net.Listener
	sockPaths []string
	mu        sync.Mutex
}

// NewAPIServer creates an APIServer configured with daemon components.
func NewAPIServer(
	cfg *config.Config,
	bl *BanList,
	stats *StatsRegistry,
	bus *EventBus,
	cs *crowdsec.Client,
) *APIServer {
	api := &APIServer{
		cfg:      cfg,
		banlist:  bl,
		stats:    stats,
		bus:      bus,
		crowdsec: cs,
	}

	mux := http.NewServeMux()

	// Content-Type wrapper
	wrapJSON := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			h(w, r)
		}
	}

	// Routes
	// /ping is a minimal unauthenticated liveness check (no sensitive data).
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	// Management API routes
	mux.HandleFunc("/health", wrapJSON(api.handleHealth))
	mux.HandleFunc("/api/tcp/health", wrapJSON(api.handleHealth))
	mux.HandleFunc("/api/guard/health", wrapJSON(api.handleHealth))

	mux.HandleFunc("/api/stats", wrapJSON(api.handleStats))
	mux.HandleFunc("/api/guard/stats", wrapJSON(api.handleStats))

	mux.HandleFunc("/api/services", wrapJSON(api.handleServices))
	mux.HandleFunc("/api/guard/services", wrapJSON(api.handleServices))

	mux.HandleFunc("/api/banlist", wrapJSON(api.handleBanlist))
	mux.HandleFunc("/api/guard/banlist", wrapJSON(api.handleBanlist))

	mux.HandleFunc("/api/unban", wrapJSON(api.handleUnban))
	mux.HandleFunc("/api/guard/unban", wrapJSON(api.handleUnban))

	mux.HandleFunc("/api/ban", wrapJSON(api.handleBan))
	mux.HandleFunc("/api/guard/ban", wrapJSON(api.handleBan))

	mux.HandleFunc("/api/events", api.handleEvents)
	mux.HandleFunc("/api/guard/events", api.handleEvents)

	api.srv = &http.Server{
		Handler: mux,
	}

	return api
}

// Start begins listening and serving the API on configured TCP and/or Unix socket listeners.
func (a *APIServer) Start() error {
	var listeners []net.Listener
	var sockPaths []string

	unixPath := a.cfg.API.Socket
	tcpAddr := a.cfg.API.Listen

	// Normalize unix socket if given in Listen
	if after, ok := strings.CutPrefix(tcpAddr, "unix://"); ok {
		unixPath = after
		tcpAddr = ""
	} else if strings.HasSuffix(tcpAddr, ".sock") || (strings.HasPrefix(tcpAddr, "/") && !strings.Contains(tcpAddr, ":")) {
		unixPath = tcpAddr
		tcpAddr = ""
	}

	// 1. Unix domain socket listener
	if unixPath != "" {
		if dir := filepath.Dir(unixPath); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		_ = os.Remove(unixPath) // clean up any stale socket

		ln, err := net.Listen("unix", unixPath)
		if err != nil {
			log.Printf("⚠️  [API] Failed to create unix socket listener on %s: %v", unixPath, err)
		} else {
			mode := a.cfg.API.FileMode()
			if err := os.Chmod(unixPath, mode); err != nil {
				log.Printf("⚠️  [API] Failed to chmod %04o on %s: %v", mode, unixPath, err)
			}
			listeners = append(listeners, ln)
			sockPaths = append(sockPaths, unixPath)
			log.Printf("✓  [API] Listening on unix socket %s (mode %04o)", unixPath, mode)
		}
	}

	// 2. TCP listener (if specified and not empty)
	if tcpAddr != "" {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			if len(listeners) == 0 {
				return fmt.Errorf("starting API TCP listener on %s: %w", tcpAddr, err)
			}
			log.Printf("⚠️  [API] Failed to listen on TCP %s: %v", tcpAddr, err)
		} else {
			listeners = append(listeners, ln)
			log.Printf("✓  [API] Listening on TCP http://%s", tcpAddr)
		}
	}

	if len(listeners) == 0 {
		return fmt.Errorf("no API listeners configured or available (tcp: %q, socket: %q)", tcpAddr, unixPath)
	}

	a.mu.Lock()
	a.listeners = listeners
	a.sockPaths = sockPaths
	a.mu.Unlock()

	var wg sync.WaitGroup
	errCh := make(chan error, len(listeners))

	for _, ln := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			if err := a.srv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) && err != http.ErrServerClosed {
				errCh <- err
			}
		}(ln)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// Close gracefully stops the HTTP server and removes any created unix domain sockets.
func (a *APIServer) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var firstErr error
	if a.srv != nil {
		firstErr = a.srv.Close()
	}
	for _, ln := range a.listeners {
		_ = ln.Close()
	}
	a.listeners = nil

	for _, sp := range a.sockPaths {
		_ = os.Remove(sp)
	}
	a.sockPaths = nil

	return firstErr
}

func (a *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	csStatus := "disabled"
	csDecisions := 0

	if a.cfg.CrowdSec.Enabled && a.crowdsec != nil {
		csStatus = "connected"
		ipCount, rangeCount := a.crowdsec.DecisionCount()
		csDecisions = ipCount + rangeCount
		if _, err := a.crowdsec.LastSync(); err != nil {
			csStatus = "sync_error"
		}
	}

	resp := map[string]any{
		"status":      status,
		"version":     a.cfg.Version,
		"plugin":      "tcp-warden",
		"active_bans": a.banlist.Count(),
		"crowdsec": map[string]any{
			"status":    csStatus,
			"decisions": csDecisions,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(a.stats.Snapshot())
}

func (a *APIServer) handleServices(w http.ResponseWriter, r *http.Request) {
	type svcSummary struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Listen   string `json:"listen"`
		Upstream string `json:"upstream"`
		Enabled  bool   `json:"enabled"`
	}

	res := make([]svcSummary, 0, len(a.cfg.Services))
	for name, s := range a.cfg.Services {
		res = append(res, svcSummary{
			Name:     name,
			Protocol: s.Protocol,
			Listen:   s.Listen,
			Upstream: s.Upstream,
			Enabled:  s.IsEnabled(),
		})
	}
	_ = json.NewEncoder(w).Encode(res)
}

func (a *APIServer) handleBanlist(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(a.banlist.All())
}

func (a *APIServer) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" || net.ParseIP(req.IP) == nil {
		http.Error(w, `{"error":"invalid or missing ip"}`, http.StatusBadRequest)
		return
	}

	unbanned := a.banlist.Unban(req.IP)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"unbanned": unbanned,
		"ip":       req.IP,
	})
}

func (a *APIServer) handleBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" || net.ParseIP(req.IP) == nil {
		http.Error(w, `{"error":"invalid or missing ip"}`, http.StatusBadRequest)
		return
	}

	dur := a.cfg.Global.BanDuration.Duration()
	if req.Duration != "" {
		parsed, err := time.ParseDuration(req.Duration)
		if err == nil {
			dur = parsed
		}
	}

	reason := req.Reason
	if reason == "" {
		reason = "manual_admin_ban"
	}

	a.banlist.Ban(req.IP, reason, "api", dur)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"banned":   true,
		"ip":       req.IP,
		"duration": dur.String(),
		"reason":   reason,
	})
}

func (a *APIServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	events, unsubscribe := a.bus.Subscribe(100)
	defer unsubscribe()

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
