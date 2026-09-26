package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/crowdsec"
	"github.com/routewarden/tcp-warden/geoip"
	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Pipeline processes a single accepted TCP connection through all policy stages.
type Pipeline struct {
	cfg      *config.Config
	banlist  *BanList
	failures *FailureTracker
	limiter  *RateLimiter
	bus      *EventBus
	stats    *StatsRegistry
	logger   *LogWriter
	crowdsec *crowdsec.Client
}

// NewPipeline creates a Pipeline wired to shared daemon components.
func NewPipeline(
	cfg *config.Config,
	bl *BanList,
	ft *FailureTracker,
	rl *RateLimiter,
	bus *EventBus,
	stats *StatsRegistry,
	logger *LogWriter,
	cs *crowdsec.Client,
) *Pipeline {
	return &Pipeline{
		cfg:      cfg,
		banlist:  bl,
		failures: ft,
		limiter:  rl,
		bus:      bus,
		stats:    stats,
		logger:   logger,
		crowdsec: cs,
	}
}

// Handle runs the 8-stage pipeline for an accepted client connection.
func (p *Pipeline) Handle(ctx context.Context, conn net.Conn, svc *config.ServiceConfig) {
	defer conn.Close()

	start := time.Now()
	clientIP := parseClientIP(conn.RemoteAddr().String())

	st := p.stats.GetOrCreate(svc.Name)
	st.ConnAccepted()
	defer st.ConnClosed()

	// Stage 1: GeoIP Lookup
	geo := geoip.LookupIP(clientIP)

	// Stage 2: Active Banlist Check
	if ban, isBanned := p.banlist.IsBanned(clientIP); isBanned {
		st.AddBlocked()
		p.emitEvent(svc, clientIP, geo, "blocked", fmt.Sprintf("banned: %s", ban.Reason), 0, 0, start)
		p.applyResponse(conn, svc, "banned")
		return
	}

	// Stage 3: CrowdSec LAPI Bouncer Check
	if p.cfg.CrowdSec.Enabled && p.crowdsec != nil {
		if dec, hasDec := p.crowdsec.Check(clientIP); hasDec {
			if strings.EqualFold(dec.Action, "ban") {
				st.AddBlocked()
				p.emitEvent(svc, clientIP, geo, "blocked", fmt.Sprintf("crowdsec_ban: %s", dec.Scenario), 0, 0, start)
				p.applyResponse(conn, svc, "crowdsec_ban")
				return
			}
		}
	}

	// Stage 4: CIDR IP Filter Check (Service + Global)
	if p.isIPDenied(clientIP, svc) {
		st.AddBlocked()
		p.emitEvent(svc, clientIP, geo, "blocked", "ip_denied", 0, 0, start)
		p.applyResponse(conn, svc, "ip_denied")
		return
	}

	// Stage 5: Geo-block Check (Country deny/allow)
	if p.isCountryBlocked(geo.CountryCode, svc) {
		st.AddBlocked()
		p.emitEvent(svc, clientIP, geo, "blocked", fmt.Sprintf("country_blocked: %s", geo.CountryCode), 0, 0, start)
		p.applyResponse(conn, svc, "country_blocked")
		return
	}

	// Stage 6: Rate Limiting (Token Bucket)
	connsPerMin := svc.RateLimit.ConnectionsPerMinute
	burst := svc.RateLimit.Burst
	if connsPerMin > 0 {
		if !p.limiter.Allow(svc.Name, clientIP, connsPerMin, burst) {
			st.AddBlocked()
			p.emitEvent(svc, clientIP, geo, "blocked", "rate_limit_exceeded", 0, 0, start)
			p.applyResponse(conn, svc, "rate_limit_exceeded")
			return
		}
	}

	// Stage 7: Protocol Validation and Upstream Connection
	if !isStandardProtocol(svc.Protocol) {
		if !plugins.IsActive(svc.Protocol) {
			st.AddBlocked()
			status, reason, _ := plugins.GetStatus(svc.Protocol)
			p.emitEvent(svc, clientIP, geo, "blocked", fmt.Sprintf("plugin_unavailable: %s (%s)", status, reason), 0, 0, start)
			p.applyResponse(conn, svc, "plugin_unavailable")
			return
		}
	}

	targetUpstream, err := svc.ResolveUpstream(conn.LocalAddr())
	if err != nil {
		targetUpstream = svc.Upstream
	}
	upstream, err := protocol.DialUpstream(targetUpstream)
	if err != nil {
		st.AddBlocked()
		p.emitEvent(svc, clientIP, geo, "blocked", "upstream_connect_failed", 0, 0, start)
		return
	}
	defer upstream.Close()

	bytesIn, bytesOut, wasBlocked, reason := p.proxyWithInspection(ctx, conn, upstream, svc, clientIP, geo)

	// Stage 8: Accounting and Security Event Logging
	st.AddBytes(bytesIn, bytesOut)
	if wasBlocked {
		st.AddBlocked()
		p.emitEvent(svc, clientIP, geo, "blocked", reason, bytesIn, bytesOut, start)
	} else {
		st.AddAllowed()
		p.emitEvent(svc, clientIP, geo, "allowed", "session_complete", bytesIn, bytesOut, start)
	}
}

func isStandardProtocol(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "ssh", "smtp", "pop3", "imap", "tcp", "generic":
		return true
	default:
		return false
	}
}

func (p *Pipeline) proxyWithInspection(
	ctx context.Context,
	client net.Conn,
	upstream net.Conn,
	svc *config.ServiceConfig,
	clientIP string,
	geo geoip.GeoResult,
) (int64, int64, bool, string) {
	onFailure := func() {
		p.recordAuthFailure(svc, clientIP, geo)
	}

	switch svc.Protocol {
	case "ssh":
		return p.handleSSH(client, upstream, svc, onFailure)
	case "smtp":
		return p.handleSMTP(client, upstream, svc, onFailure, clientIP, geo)
	case "pop3":
		return p.handlePOP3(client, upstream, svc, onFailure, clientIP, geo)
	case "imap":
		return p.handleIMAP(client, upstream, svc, onFailure, clientIP, geo)
	case "tcp", "generic":
		res := protocol.Proxy(client, upstream)
		return res.BytesIn, res.BytesOut, false, ""
	default:
		// Route through modular plugin architecture
		return p.handlePlugin(client, upstream, svc, onFailure, clientIP, geo)
	}
}

func (p *Pipeline) handlePlugin(
	client net.Conn,
	upstream net.Conn,
	svc *config.ServiceConfig,
	onFailure func(),
	clientIP string,
	geo geoip.GeoResult,
) (int64, int64, bool, string) {
	plugin, ok := plugins.Get(svc.Protocol)
	if !ok {
		log.Printf("⚠️ [WARN] Service %q: connection rejected because plugin for protocol %q is not installed",
			svc.Name, svc.Protocol)
		p.applyResponse(client, svc, "plugin_not_installed")
		return 0, 0, true, "plugin_not_installed"
	}

	// 1. Verify plugin health status (Auto-disable enforcement)
	if !plugins.IsActive(svc.Protocol) {
		status, reason, testErr := plugins.GetStatus(svc.Protocol)
		log.Printf("⚠️ [WARN] Service %q: connection rejected because plugin %q is %s (%s: %v)",
			svc.Name, plugin.Manifest().Name, status, reason, testErr)
		p.applyResponse(client, svc, "plugin_disabled")
		return 0, 0, true, fmt.Sprintf("plugin_disabled: %s", status)
	}

	// 2. Instantiate inspector with service options
	inspector, err := plugin.CreateInspector(svc.GetPluginOptions())
	if err != nil {
		log.Printf("⚠️ [WARN] Service %q: failed creating inspector for plugin %q: %v",
			svc.Name, plugin.Manifest().Name, err)
		res := protocol.Proxy(client, upstream)
		return res.BytesIn, res.BytesOut, false, ""
	}

	// 3. Prepare plugin context with security callbacks
	pCtx := &sdk.DefaultContext{
		ServiceName:   svc.Name,
		ClientAddress: clientIP,
		AuthFailureFunc: onFailure,
		SecurityFunc: func(action, reason string) {
			p.emitEvent(svc, clientIP, geo, action, reason, 0, 0, time.Now())
		},
	}

	// 4. Run protocol inspection
	res, wasBlocked, reason, _ := inspector.Run(pCtx, client, upstream)
	return res.BytesIn, res.BytesOut, wasBlocked, reason
}

func (p *Pipeline) handleSSH(client, upstream net.Conn, svc *config.ServiceConfig, onFailure func()) (int64, int64, bool, string) {
	inspector := protocol.SSHInspector{}
	reader, res := inspector.Inspect(client)

	if res.IsSSH1 {
		protocol.RejectSSH1(client)
		return 0, 0, true, "ssh1_rejected"
	}

	bufferedClient := &protocol.BufferedConn{
		Reader: reader,
		Conn:   client,
	}

	monitor := protocol.NewSSHAuthMonitor(onFailure)
	wrappedUpstream := monitor.WrapUpstream(upstream)

	proxyRes := protocol.Proxy(bufferedClient, wrappedUpstream)
	return proxyRes.BytesIn, proxyRes.BytesOut, false, ""
}

func (p *Pipeline) handleSMTP(client, upstream net.Conn, svc *config.ServiceConfig, onFailure func(), clientIP string, geo geoip.GeoResult) (int64, int64, bool, string) {
	opts := protocol.SMTPInspectorOptions{
		BlockedSenderDomains: svc.SMTP.BlockedSenderDomains,
		RequireSTARTTLS:      svc.SMTP.RequireSTARTTLS,
		OnAuthFailure:        onFailure,
	}
	proxy := protocol.NewSMTPProxy(client, upstream, opts)
	res, wasBlocked, reason := proxy.Run()
	return res.BytesIn, res.BytesOut, wasBlocked, reason
}

func (p *Pipeline) handlePOP3(client, upstream net.Conn, svc *config.ServiceConfig, onFailure func(), clientIP string, geo geoip.GeoResult) (int64, int64, bool, string) {
	opts := protocol.POP3InspectorOptions{
		OnAuthFailure: onFailure,
	}
	proxy := protocol.NewPOP3Proxy(client, upstream, opts)
	res, _, _ := proxy.Run()
	return res.BytesIn, res.BytesOut, false, ""
}

func (p *Pipeline) handleIMAP(client, upstream net.Conn, svc *config.ServiceConfig, onFailure func(), clientIP string, geo geoip.GeoResult) (int64, int64, bool, string) {
	opts := protocol.IMAPInspectorOptions{
		OnAuthFailure: onFailure,
	}
	proxy := protocol.NewIMAPProxy(client, upstream, opts)
	res, _, _ := proxy.Run()
	return res.BytesIn, res.BytesOut, false, ""
}

func (p *Pipeline) recordAuthFailure(svc *config.ServiceConfig, clientIP string, geo geoip.GeoResult) {
	window := 15 * time.Minute
	count := p.failures.RecordFailure(svc.Name, clientIP, window)

	threshold := svc.BanAfterFailures
	if threshold <= 0 {
		threshold = svc.MaxAuthFailures
	}
	if threshold <= 0 {
		threshold = p.cfg.Global.BanAfterFailures
	}

	p.emitEvent(svc, clientIP, geo, "auth_failure", fmt.Sprintf("attempt %d/%d", count, threshold), 0, 0, time.Now())

	if threshold > 0 && count >= threshold {
		dur := svc.BanDuration.Duration()
		if dur <= 0 {
			dur = p.cfg.Global.BanDuration.Duration()
		}
		p.banlist.Ban(clientIP, fmt.Sprintf("max_auth_failures_exceeded (%d)", count), svc.Name, dur)
		p.emitEvent(svc, clientIP, geo, "banned", fmt.Sprintf("banned for %s", dur), 0, 0, time.Now())
	}
}

func (p *Pipeline) isIPDenied(clientIP string, svc *config.ServiceConfig) bool {
	parsed := net.ParseIP(clientIP)
	if parsed == nil {
		return true
	}

	// 1. Service Allowlist (if non-empty, must match)
	if len(svc.IPFilter.Allow) > 0 {
		matched := false
		for _, allowStr := range svc.IPFilter.Allow {
			if matchIP(parsed, allowStr) {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
	}

	// 2. Global Allowlist (if configured and service didn't override)
	if len(svc.IPFilter.Allow) == 0 && len(p.cfg.Global.IPFilter.Allow) > 0 {
		matched := false
		for _, allowStr := range p.cfg.Global.IPFilter.Allow {
			if matchIP(parsed, allowStr) {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
	}

	// 3. Service Denylist
	for _, denyStr := range svc.IPFilter.Deny {
		if matchIP(parsed, denyStr) {
			return true
		}
	}

	// 4. Global Denylist
	for _, denyStr := range p.cfg.Global.IPFilter.Deny {
		if matchIP(parsed, denyStr) {
			return true
		}
	}

	return false
}

func (p *Pipeline) isCountryBlocked(countryCode string, svc *config.ServiceConfig) bool {
	if countryCode == "" || countryCode == "LAN" {
		return false
	}
	codeUpper := strings.ToUpper(countryCode)

	// Check allowlists (if specified, country must be in list)
	if len(svc.GeoBlock.AllowCountries) > 0 {
		allowed := false
		for _, c := range svc.GeoBlock.AllowCountries {
			if strings.EqualFold(c, codeUpper) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	} else if len(p.cfg.Global.GeoBlock.AllowCountries) > 0 {
		allowed := false
		for _, c := range p.cfg.Global.GeoBlock.AllowCountries {
			if strings.EqualFold(c, codeUpper) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}

	// Check denylists
	for _, c := range svc.GeoBlock.DenyCountries {
		if strings.EqualFold(c, codeUpper) {
			return true
		}
	}
	for _, c := range p.cfg.Global.GeoBlock.DenyCountries {
		if strings.EqualFold(c, codeUpper) {
			return true
		}
	}

	return false
}

func (p *Pipeline) applyResponse(conn net.Conn, svc *config.ServiceConfig, reason string) {
	mode := strings.ToLower(svc.Response.Mode)
	switch mode {
	case "tarpit":
		delay := time.Duration(svc.Response.TarpitMs) * time.Millisecond
		if delay > 0 {
			time.Sleep(delay)
		}
		conn.Close()
	case "reject":
		msg := svc.Response.RejectMessage
		if msg == "" {
			msg = "Connection rejected by RouteWarden"
		}
		conn.Write([]byte(msg + "\r\n"))
		conn.Close()
	case "silent", "drop":
		fallthrough
	default:
		conn.Close()
	}
}

func (p *Pipeline) emitEvent(
	svc *config.ServiceConfig,
	clientIP string,
	geo geoip.GeoResult,
	action string,
	reason string,
	bytesIn int64,
	bytesOut int64,
	start time.Time,
) {
	ev := SecurityEvent{
		Type:        "security_event",
		Timestamp:   time.Now().UTC(),
		Plugin:      "tcp-warden",
		Service:     svc.Name,
		Protocol:    svc.Protocol,
		ClientIP:    clientIP,
		CountryCode: geo.CountryCode,
		CountryName: geo.CountryName,
		FlagEmoji:   geo.FlagEmoji,
		Action:      action,
		Reason:      reason,
		BytesIn:     bytesIn,
		BytesOut:    bytesOut,
		DurationMs:  time.Since(start).Milliseconds(),
	}

	if p.bus != nil {
		p.bus.Publish(ev)
	}
	if p.logger != nil {
		_ = p.logger.Write(ev)
	}
}

func parseClientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func matchIP(ip net.IP, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			return ipNet.Contains(ip)
		}
		return false
	}
	parsed := net.ParseIP(pattern)
	if parsed == nil {
		return false
	}
	return ip.Equal(parsed)
}
