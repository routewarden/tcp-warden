package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

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

	listeners map[string]net.Listener
	mu        sync.Mutex
	wg        sync.WaitGroup
}

// NewDaemon initializes a Daemon instance from configuration.
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	// 1. Run self-tests for all modular plugins before accepting connections
	pluginResults := plugins.RunSelfTests()
	for name, res := range pluginResults {
		if !res.Passed {
			log.Printf("⚠️  [PLUGIN] %s self-test FAILED and is DISABLED: %v", name, res.Error)
		}
	}

	// Check if any active service uses a disabled plugin
	for name, svc := range cfg.Services {
		if svc.IsEnabled() {
			switch svc.Protocol {
			case "ssh", "smtp", "pop3", "imap", "tcp", "generic":
				// Standard protocol
			default:
				if !plugins.IsActive(svc.Protocol) {
					st, testErr := plugins.GetStatus(svc.Protocol)
					log.Printf("⚠️  [WARN] Service %q uses protocol %q, but plugin is %s (reason: %v). Inbound connections will be rejected.",
						name, svc.Protocol, st, testErr)
				}
			}
		}
	}

	// Initialize GeoIP if DB path configured
	geoip.InitGeoIP(cfg.Global.GeoIPDB)

	bl := NewBanList()
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
		listeners: make(map[string]net.Listener),
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

	// 3. Start listeners for all enabled services
	for name, svc := range d.cfg.Services {
		if !svc.IsEnabled() {
			continue
		}

		ln, err := net.Listen("tcp", svc.Listen)
		if err != nil {
			d.Stop()
			return fmt.Errorf("starting listener for service %q on %s: %w", name, svc.Listen, err)
		}

		d.mu.Lock()
		d.listeners[name] = ln
		d.mu.Unlock()

		d.wg.Add(1)
		go d.serveService(ctx, ln, svc)
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
				return
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
	d.listeners = make(map[string]net.Listener)

	if d.apiServer != nil {
		d.apiServer.Close()
	}
	if d.crowdsec != nil {
		d.crowdsec.Stop()
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
