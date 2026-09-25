package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/crowdsec"
)

// APIServer serves management, metrics, and SSE event streaming.
type APIServer struct {
	cfg      *config.Config
	banlist  *BanList
	stats    *StatsRegistry
	bus      *EventBus
	crowdsec *crowdsec.Client
	srv      *http.Server
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

	// Authentication wrapper
	wrapAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := cfg.API.AuthToken
			if token != "" {
				authHeader := r.Header.Get("Authorization")
				customHeader := r.Header.Get("X-Warden-Token")
				expectedBearer := "Bearer " + token
				if authHeader != expectedBearer && customHeader != token {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			h(w, r)
		}
	}

	// Routes
	mux.HandleFunc("/health", api.handleHealth)
	mux.HandleFunc("/api/tcp/health", api.handleHealth)
	mux.HandleFunc("/api/guard/health", api.handleHealth)

	mux.HandleFunc("/api/stats", wrapAuth(api.handleStats))
	mux.HandleFunc("/api/guard/stats", wrapAuth(api.handleStats))

	mux.HandleFunc("/api/services", wrapAuth(api.handleServices))
	mux.HandleFunc("/api/guard/services", wrapAuth(api.handleServices))

	mux.HandleFunc("/api/banlist", wrapAuth(api.handleBanlist))
	mux.HandleFunc("/api/guard/banlist", wrapAuth(api.handleBanlist))

	mux.HandleFunc("/api/unban", wrapAuth(api.handleUnban))
	mux.HandleFunc("/api/guard/unban", wrapAuth(api.handleUnban))

	mux.HandleFunc("/api/ban", wrapAuth(api.handleBan))
	mux.HandleFunc("/api/guard/ban", wrapAuth(api.handleBan))

	mux.HandleFunc("/api/events", api.handleEvents)
	mux.HandleFunc("/api/guard/events", api.handleEvents)

	api.srv = &http.Server{
		Addr:    cfg.API.Listen,
		Handler: mux,
	}

	return api
}

// Start begins listening and serving the API.
func (a *APIServer) Start() error {
	return a.srv.ListenAndServe()
}

// Close gracefully stops the HTTP server.
func (a *APIServer) Close() error {
	if a.srv != nil {
		return a.srv.Close()
	}
	return nil
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

	if req.IP == "" {
		http.Error(w, `{"error":"ip is required"}`, http.StatusBadRequest)
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

	if req.IP == "" {
		http.Error(w, `{"error":"ip is required"}`, http.StatusBadRequest)
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
	// Authenticate SSE stream if token configured
	token := a.cfg.API.AuthToken
	if token != "" {
		authHeader := r.Header.Get("Authorization")
		queryToken := r.URL.Query().Get("token")
		if authHeader != "Bearer "+token && queryToken != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

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
