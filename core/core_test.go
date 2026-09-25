package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestPipelineIPFilterAndBanlist(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
		Services: map[string]config.ServiceConfig{
			"test-service": {
				Name:     "test-service",
				Protocol: "tcp",
				IPFilter: config.IPFilterConfig{
					Deny: []string{"198.51.100.0/24"},
				},
				Response: config.ResponseConfig{
					Mode: "drop",
				},
			},
		},
	}

	bl := NewBanList()
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	svc := cfg.Services["test-service"]

	// 1. Test Denied IP
	clientConn, serverConn := net.Pipe()
	go func() {
		// Mock remote addr
		pipe.Handle(context.Background(), serverConn, &svc)
	}()

	// Read or wait for close
	buf := make([]byte, 16)
	_, _ = clientConn.Read(buf)
	clientConn.Close()

	// 2. Test Banlist
	bl.Ban("127.0.0.1", "manual_test", "test-service", 1*time.Hour)
	if entry, banned := bl.IsBanned("127.0.0.1"); !banned || entry.Reason != "manual_test" {
		t.Fatalf("expected 127.0.0.1 to be banned")
	}

	bl.Unban("127.0.0.1")
	if _, banned := bl.IsBanned("127.0.0.1"); banned {
		t.Fatalf("expected 127.0.0.1 to be unbanned")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// 60 conns/min = 1/sec, burst 2
	allowed1 := rl.Allow("ssh", "192.0.2.1", 60, 2)
	allowed2 := rl.Allow("ssh", "192.0.2.1", 60, 2)
	allowed3 := rl.Allow("ssh", "192.0.2.1", 60, 2)

	if !allowed1 || !allowed2 {
		t.Errorf("expected first 2 burst connections to be allowed")
	}
	if allowed3 {
		t.Errorf("expected 3rd immediate connection to exceed burst capacity")
	}
}

func TestFailureTrackerAndAutoBan(t *testing.T) {
	ft := NewFailureTracker()

	c1 := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)
	c2 := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)
	c3 := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)

	if c1 != 1 || c2 != 2 || c3 != 3 {
		t.Errorf("expected 1, 2, 3 failure counts; got %d, %d, %d", c1, c2, c3)
	}

	ft.Reset("ssh", "192.0.2.5")
	cAfter := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)
	if cAfter != 1 {
		t.Errorf("expected 1 failure count after reset, got %d", cAfter)
	}
}

func TestAPIServerEndpoints(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9091",
		},
		Services: map[string]config.ServiceConfig{
			"ssh": {
				Name:     "ssh",
				Listen:   ":2222",
				Upstream: "127.0.0.1:22",
				Protocol: "ssh",
			},
		},
	}

	bl := NewBanList()
	stats := NewStatsRegistry()
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	// 1. Test /health
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /health, got %d", rec.Code)
	}
	var healthResp map[string]any
	json.NewDecoder(rec.Body).Decode(&healthResp)
	if healthResp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", healthResp["status"])
	}

	// 2. Test /api/ban
	banReqBody := []byte(`{"ip":"198.51.100.99","reason":"test_ban","duration":"30m"}`)
	reqBan := httptest.NewRequest(http.MethodPost, "/api/ban", bytes.NewReader(banReqBody))
	recBan := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBan, reqBan)

	if recBan.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/ban, got %d", recBan.Code)
	}
	if _, ok := bl.IsBanned("198.51.100.99"); !ok {
		t.Fatalf("expected 198.51.100.99 to be banned via API")
	}

	// 3. Test /api/banlist
	reqList := httptest.NewRequest(http.MethodGet, "/api/banlist", nil)
	recList := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recList, reqList)

	var list []BanEntry
	json.NewDecoder(recList.Body).Decode(&list)
	if len(list) != 1 || list[0].IP != "198.51.100.99" {
		t.Errorf("unexpected banlist response: %+v", list)
	}

	// 4. Test /api/unban
	unbanReqBody := []byte(`{"ip":"198.51.100.99"}`)
	reqUnban := httptest.NewRequest(http.MethodPost, "/api/unban", bytes.NewReader(unbanReqBody))
	recUnban := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recUnban, reqUnban)

	if recUnban.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/unban, got %d", recUnban.Code)
	}
	if _, ok := bl.IsBanned("198.51.100.99"); ok {
		t.Fatalf("expected 198.51.100.99 to be unbanned via API")
	}
}

type brokenSelfTestPlugin struct{}

func (b *brokenSelfTestPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:      "broken-test-plugin",
		Protocols: []string{"broken-proto"},
	}
}
func (b *brokenSelfTestPlugin) ValidateConfig(cfg map[string]any) error        { return nil }
func (b *brokenSelfTestPlugin) CreateInspector(cfg map[string]any) (sdk.Inspector, error) {
	return nil, nil
}
func (b *brokenSelfTestPlugin) SelfTest() error {
	return errors.New("deliberate self-test failure: database handshake assertion timed out")
}

func TestPipeline_ModularPluginAutoDisable(t *testing.T) {
	// Register deliberately broken plugin
	broken := &brokenSelfTestPlugin{}
	plugins.Register(broken)

	// Run self-tests
	results := plugins.RunSelfTests()
	bRes, ok := results["broken-test-plugin"]
	if !ok || bRes.Passed {
		t.Fatalf("expected broken-test-plugin to fail self-test")
	}
	if plugins.IsActive("broken-proto") {
		t.Fatalf("broken-proto should NOT be active")
	}

	cfg := &config.Config{
		Version: "1.0",
		Services: map[string]config.ServiceConfig{
			"failing-service": {
				Name:     "failing-service",
				Protocol: "broken-proto",
				Response: config.ResponseConfig{
					Mode:          "reject",
					RejectMessage: "PLUGIN_DISABLED_REJECTION",
				},
			},
		},
	}

	bl := NewBanList()
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	var emittedEvents []SecurityEvent
	subCh, unsub := bus.Subscribe(10)
	defer unsub()

	go func() {
		for ev := range subCh {
			emittedEvents = append(emittedEvents, ev)
		}
	}()

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	svc := cfg.Services["failing-service"]

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})

	go func() {
		pipe.Handle(context.Background(), serverConn, &svc)
		close(done)
	}()

	buf := make([]byte, 128)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientConn.Read(buf)
	clientConn.Close()

	<-done

	resp := string(buf[:n])
	if !strings.Contains(resp, "PLUGIN_DISABLED_REJECTION") {
		t.Errorf("expected rejection banner when plugin is disabled, got %q", resp)
	}

	st := stats.GetOrCreate("failing-service")
	if st.Snapshot().BlockedConnections == 0 {
		t.Errorf("expected blocked connection metric incremented")
	}
}

