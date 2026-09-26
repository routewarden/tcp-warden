package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/crowdsec"
	"github.com/routewarden/tcp-warden/geoip"
	"github.com/routewarden/tcp-warden/plugins"
	_ "github.com/routewarden/tcp-warden/plugins/all"
)

// Daemon coordinates listeners, pipeline, CrowdSec client, and API server.
type Daemon struct {
	cfg       *config.Config
	banlist   *BanList
	failures  *FailureTracker
	limiter   *RateLimiter
	stats     *StatsRegistry
	bus       *EventBus
	logger    *LogWriter
	crowdsec  *crowdsec.Client
	pipeline  *Pipeline
	apiServer *APIServer

	listeners []net.Listener
	mu        sync.Mutex
	wg        sync.WaitGroup
}

// NewDaemon initializes a Daemon instance from configuration.
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	// 0. Sync plugins declared with a source in configuration (using cache or pulling fresh)
	for name, entry := range cfg.Plugins.Entries {
		if entry.Source != "" {
			res, err := plugins.SyncPluginFromSource(name, entry.Source, plugins.InstallOptions{
				NoBuild: true,
			})
			if err != nil {
				log.Printf("⚠️  [PLUGIN SYNC] Failed syncing plugin %q from %s: %v", name, entry.Source, err)
			} else if !res.TestPassed {
				log.Printf("⚠️  [PLUGIN SYNC] Plugin %q tests FAILED; plugin remains DISABLED", name)
			}
		}
	}

	// 1. Apply configured plugin enablement (pre-shipped non-standard plugins disabled by default)
	enabledList := append([]string(nil), cfg.Plugins.Enabled...)
	disabledList := append([]string(nil), cfg.Plugins.Disabled...)

	if pEnabled, pDisabled, err := plugins.GetPluginEnablement(plugins.ResolveProjectDir("")); err == nil {
		for _, pe := range pEnabled {
			if _, exists := cfg.Plugins.Entries[pe]; !exists {
				disabledList = removeFromList(disabledList, pe)
				if !contains(enabledList, pe) {
					enabledList = append(enabledList, pe)
				}
			}
		}
		for _, pd := range pDisabled {
			if _, exists := cfg.Plugins.Entries[pd]; !exists {
				enabledList = removeFromList(enabledList, pd)
				if !contains(disabledList, pd) {
					disabledList = append(disabledList, pd)
				}
			}
		}
	}

	pluginErrs := plugins.ApplyConfiguration(enabledList, disabledList)
	for name, err := range pluginErrs {
		log.Printf("⚠️  [PLUGIN] %q self-test FAILED and remains DISABLED: %v", name, err)
	}

	for _, pInfo := range plugins.List() {
		if pInfo.Enabled && pInfo.Status == plugins.StatusActive {
			log.Printf("✓  [PLUGIN] %s (%s) is ACTIVE and healthy", pInfo.Name, pInfo.Version)
		}
	}

	// Check if any active service uses a disabled plugin
	for name, svc := range cfg.Services {
		if svc.IsEnabled() {
			switch strings.ToLower(strings.TrimSpace(svc.Protocol)) {
			case "ssh", "smtp", "pop3", "imap", "tcp", "generic":
				// Standard protocol
			default:
				if !plugins.IsActive(svc.Protocol) {
					st, reason, testErr := plugins.GetStatus(svc.Protocol)
					log.Printf("⚠️  [WARN] Service %q uses protocol %q, but plugin is %s (%s: %v). Inbound connections will be rejected.",
						name, svc.Protocol, st, reason, testErr)
				}
			}
		}
	}

	// Initialize GeoIP if DB path configured
	geoip.InitGeoIP(cfg.Global.GeoIPDB)

	bl := NewBanList(cfg.Global.DataDir)
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	stats := NewStatsRegistry()
	bus := NewEventBus()

	var logger *LogWriter
	if cfg.Global.LogFile != "" {
		l, err := NewLogWriter(cfg.Global.LogFile)
		if err != nil {
			log.Printf("⚠️ Warning: could not initialize log writer for %s: %v", cfg.Global.LogFile, err)
		} else {
			logger = l
		}
	}

	var cs *crowdsec.Client
	if cfg.CrowdSec.Enabled {
		cs = crowdsec.NewClient(crowdsec.Config{
			LAPIURL:        cfg.CrowdSec.LAPIURL,
			APIKey:         cfg.CrowdSec.APIKey,
			UpdateInterval: cfg.CrowdSec.UpdateFrequency.Duration(),
		})
	}

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, logger, cs)

	var apiSrv *APIServer
	if cfg.API.Enabled {
		apiSrv = NewAPIServer(cfg, bl, stats, bus, cs)
	}

	return &Daemon{
		cfg:       cfg,
		banlist:   bl,
		failures:  ft,
		limiter:   rl,
		stats:     stats,
		bus:       bus,
		logger:    logger,
		crowdsec:  cs,
		pipeline:  pipe,
		apiServer: apiSrv,
		listeners: make([]net.Listener, 0),
	}, nil
}

// Run starts all listeners and services, blocking until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	// 1. Start CrowdSec sync if enabled
	if d.crowdsec != nil {
		if err := d.crowdsec.Start(ctx); err != nil {
			log.Printf("⚠️ Failed to start CrowdSec sync: %v", err)
		}
	}

	// 2. Start API server if enabled
	if d.apiServer != nil {
		go func() {
			if err := d.apiServer.Start(); err != nil && err != net.ErrClosed {
				log.Printf("⚠️ API server error: %v", err)
			}
		}()
	}

	// 3. Start listeners for all enabled services (including port ranges)
	for name, svc := range d.cfg.Services {
		if !svc.IsEnabled() {
			continue
		}

		lHost, ports, err := svc.ListenPorts()
		if err != nil {
			d.Stop()
			return fmt.Errorf("parsing listen address for service %q (%s): %w", name, svc.Listen, err)
		}

		for _, port := range ports {
			listenAddr := config.FormatHostPort(lHost, port)
			ln, err := net.Listen("tcp", listenAddr)
			if err != nil {
				d.Stop()
				return fmt.Errorf("starting listener for service %q on %s: %w", name, listenAddr, err)
			}

			d.mu.Lock()
			d.listeners = append(d.listeners, ln)
			d.mu.Unlock()

			d.wg.Add(1)
			go d.serveService(ctx, ln, svc)
		}
	}

	// Wait for context cancellation
	<-ctx.Done()
	d.Stop()
	d.wg.Wait()
	return nil
}

func (d *Daemon) serveService(ctx context.Context, ln net.Listener, svc config.ServiceConfig) {
	defer d.wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				// Fatal: listener was deliberately closed.
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Transient OS error (e.g. "too many open files") — log and retry.
				log.Printf("⚠️  [%s] Accept error (retrying in 100ms): %v", svc.Name, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go d.pipeline.Handle(ctx, conn, &svc)
	}
}

// Stop cleanly terminates all listeners, API server, and logs.
func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, ln := range d.listeners {
		ln.Close()
	}
	d.listeners = nil

	if d.apiServer != nil {
		d.apiServer.Close()
	}
	if d.crowdsec != nil {
		d.crowdsec.Stop()
	}
	if d.limiter != nil {
		d.limiter.Stop()
	}
	if d.failures != nil {
		d.failures.Stop()
	}
	if d.banlist != nil {
		d.banlist.Close()
	}
	if d.bus != nil {
		d.bus.Close()
	}
	if d.logger != nil {
		d.logger.Close()
	}
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func removeFromList(list []string, item string) []string {
	var res []string
	for _, s := range list {
		if !strings.EqualFold(s, item) {
			res = append(res, s)
		}
	}
	return res
}

