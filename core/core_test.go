package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/config"
	"github.com/routewarden/tcp-warden/geoip"
	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
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

	bl := NewBanList("")
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

func TestPipeline_AutoBanOnMaxAuthFailures(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
		Services: map[string]config.ServiceConfig{
			"auth-svc": {
				Name:            "auth-svc",
				Protocol:        "tcp",
				MaxAuthFailures: 3,
				BanDuration:     config.Duration(2 * time.Hour),
				Response: config.ResponseConfig{
					Mode: "drop",
				},
			},
		},
	}

	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	svc := cfg.Services["auth-svc"]
	clientIP := "203.0.113.50"

	// 1. Initial state: not banned
	if _, isBanned := bl.IsBanned(clientIP); isBanned {
		t.Fatalf("expected client %s not to be banned initially", clientIP)
	}

	// 2. Record 1st failure -> count = 1, threshold = 3 -> not banned
	pipe.recordAuthFailure(&svc, clientIP, geoip.GeoResult{})
	if _, isBanned := bl.IsBanned(clientIP); isBanned {
		t.Fatalf("expected client %s not to be banned after 1 failure", clientIP)
	}

	// 3. Record 2nd failure -> count = 2, threshold = 3 -> not banned
	pipe.recordAuthFailure(&svc, clientIP, geoip.GeoResult{})
	if _, isBanned := bl.IsBanned(clientIP); isBanned {
		t.Fatalf("expected client %s not to be banned after 2 failures", clientIP)
	}

	// 4. Record 3rd failure -> count = 3, threshold = 3 -> MUST BE BANNED!
	pipe.recordAuthFailure(&svc, clientIP, geoip.GeoResult{})
	entry, isBanned := bl.IsBanned(clientIP)
	if !isBanned {
		t.Fatalf("expected client %s to be automatically banned after reaching MaxAuthFailures", clientIP)
	}
	if !strings.Contains(entry.Reason, "max_auth_failures_exceeded") {
		t.Errorf("unexpected ban reason: %s", entry.Reason)
	}
	if entry.Service != "auth-svc" {
		t.Errorf("expected banned service to be 'auth-svc', got %s", entry.Service)
	}

	// 5. Subsequent connection from banned IP is caught at Stage 2
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	// Wrap connB with mock address
	mockConn := &mockAddrConn{Conn: connB, remoteIP: clientIP}

	done := make(chan struct{})
	go func() {
		pipe.Handle(context.Background(), mockConn, &svc)
		close(done)
	}()

	select {
	case <-done:
		// Connection handled and dropped
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for pipeline to drop banned connection")
	}

	st := stats.GetOrCreate("auth-svc")
	if st.Snapshot().BlockedConnections == 0 {
		t.Errorf("expected blocked connection count to increment for banned IP")
	}
}

type mockAddrConn struct {
	net.Conn
	remoteIP string
}

func (m *mockAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP(m.remoteIP),
		Port: 54321,
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

	bl := NewBanList("")
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

	// 5. Test invalid IP rejection on /api/ban and /api/unban
	reqBadBan := httptest.NewRequest(http.MethodPost, "/api/ban", bytes.NewReader([]byte(`{"ip":"not-an-ip"}`)))
	recBadBan := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBadBan, reqBadBan)
	if recBadBan.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid IP in ban, got %d", recBadBan.Code)
	}

	reqBadUnban := httptest.NewRequest(http.MethodPost, "/api/unban", bytes.NewReader([]byte(`{"ip":"not-an-ip"}`)))
	recBadUnban := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBadUnban, reqBadUnban)
	if recBadUnban.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid IP in unban, got %d", recBadUnban.Code)
	}
}

func TestAPIServerUnixSocket(t *testing.T) {
	sockPath := fmt.Sprintf("./tw-test-%d.sock", time.Now().UnixNano()%10000000)
	defer os.Remove(sockPath)

	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled:    true,
			Socket:     sockPath,
			SocketMode: 0666,
		},
	}

	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	go func() {
		_ = api.Start()
	}()
	defer api.Close()

	// Wait up to 2 seconds for unix socket to exist
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to unix socket %s: %v", sockPath, err)
	}
	conn.Close()

	// Make HTTP request over unix socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get("http://unix/health")
	if err != nil {
		t.Fatalf("failed GET /health over unix socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from unix socket /health, got %d", resp.StatusCode)
	}

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed decoding health json: %v", err)
	}
	if health["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", health["status"])
	}

	// Close API and verify socket cleanup
	if err := api.Close(); err != nil {
		t.Fatalf("unexpected error closing api server: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected unix socket %s to be removed on Close, but stat returned %v", sockPath, err)
	}
}

func TestEventBus_CloseSubscribeSafety(t *testing.T) {
	bus := NewEventBus()
	_, unsub := bus.Subscribe(5)
	unsub()

	bus.Close()

	// Calling Publish, Subscribe, and unsub after Close must not panic
	bus.Publish(SecurityEvent{Action: "test"})
	ch2, unsub2 := bus.Subscribe(5)
	if _, open := <-ch2; open {
		t.Errorf("expected channel from closed bus to be closed")
	}
	unsub2()
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

	// Attempt to enable it (should fail self-test)
	if err := plugins.Enable("broken-test-plugin"); err == nil {
		t.Fatalf("expected enabling broken-test-plugin to fail")
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

	bl := NewBanList("")
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

func TestPipeline_GlobalGeoBlockAllowCountries(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			GeoBlock: config.GeoBlockConfig{
				AllowCountries: []string{"US", "CA"},
			},
		},
		Services: map[string]config.ServiceConfig{
			"geo-svc": {
				Name:     "geo-svc",
				Protocol: "tcp",
				Response: config.ResponseConfig{
					Mode: "drop",
				},
			},
		},
	}

	pipe := NewPipeline(cfg, NewBanList(""), NewFailureTracker(), NewRateLimiter(), NewEventBus(), NewStatsRegistry(), nil, nil)
	svc := cfg.Services["geo-svc"]

	// "FR" is not in US/CA -> should be blocked
	if !pipe.isCountryBlocked("FR", &svc) {
		t.Errorf("expected FR to be blocked by global allowlist")
	}

	// "US" is in US/CA -> should be allowed
	if pipe.isCountryBlocked("US", &svc) {
		t.Errorf("expected US to be allowed by global allowlist")
	}
}

type mockHTTPPlugin struct {
	inspectedCount atomic.Int32
}

func (m *mockHTTPPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:      "http",
		Version:   "1.0.0",
		Protocols: []string{"http"},
	}
}

func (m *mockHTTPPlugin) ValidateConfig(map[string]any) error { return nil }
func (m *mockHTTPPlugin) CreateInspector(map[string]any) (sdk.Inspector, error) {
	return &mockHTTPInspector{plugin: m}, nil
}
func (m *mockHTTPPlugin) SelfTest() error { return nil }

type mockHTTPInspector struct {
	plugin *mockHTTPPlugin
}

func (i *mockHTTPInspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	i.plugin.inspectedCount.Add(1)
	res := protocol.Proxy(client, upstream)
	return sdk.ProxyResult{BytesIn: res.BytesIn, BytesOut: res.BytesOut}, false, "", nil
}

func findTwoPortPairs(t *testing.T) (l1, l2, u1, u2 int) {
	t.Helper()
	testL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping live socket integration test: net.Listen restricted in test environment: %v", err)
		return 0, 0, 0, 0
	}
	testL.Close()

	for port := 31000; port < 45000; port += 4 {
		lA, errA := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if errA != nil {
			continue
		}
		lB, errB := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+1))
		if errB != nil {
			lA.Close()
			continue
		}
		lC, errC := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+2))
		if errC != nil {
			lA.Close()
			lB.Close()
			continue
		}
		lD, errD := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+3))
		if errD != nil {
			lA.Close()
			lB.Close()
			lC.Close()
			continue
		}
		lA.Close()
		lB.Close()
		lC.Close()
		lD.Close()
		return port, port + 1, port + 2, port + 3
	}
	t.Fatal("could not find free port pairs")
	return 0, 0, 0, 0
}

func TestDaemon_HTTPPortRange_1to1(t *testing.T) {
	mockPlugin := &mockHTTPPlugin{}
	plugins.Register(mockPlugin)

	l1, l2, u1, u2 := findTwoPortPairs(t)

	// Upstream 1
	srv1 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response-from-upstream-1"))
	})}
	lnU1, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", u1))
	if err != nil {
		t.Fatalf("failed to listen on upstream 1: %v", err)
	}
	go srv1.Serve(lnU1)
	defer srv1.Close()

	// Upstream 2
	srv2 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response-from-upstream-2"))
	})}
	lnU2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", u2))
	if err != nil {
		t.Fatalf("failed to listen on upstream 2: %v", err)
	}
	go srv2.Serve(lnU2)
	defer srv2.Close()

	cfg := &config.Config{
		Version: "1.0",
		Plugins: config.PluginsConfig{
			Enabled: []string{"http"},
		},
		Services: map[string]config.ServiceConfig{
			"http-1to1": {
				Name:     "http-1to1",
				Listen:   fmt.Sprintf("127.0.0.1:%d-%d", l1, l2),
				Upstream: fmt.Sprintf("127.0.0.1:%d-%d", u1, u2),
				Protocol: "http",
			},
		},
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("daemon Run exited prematurely: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Query Port 1 -> Should map to Upstream 1
	resp1, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l1))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l1, err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)
	if string(body1) != "response-from-upstream-1" {
		t.Errorf("port %d expected response from upstream 1, got %q", l1, string(body1))
	}

	// 2. Query Port 2 -> Should map to Upstream 2
	resp2, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l2))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l2, err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "response-from-upstream-2" {
		t.Errorf("port %d expected response from upstream 2, got %q", l2, string(body2))
	}

	if mockPlugin.inspectedCount.Load() < 2 {
		t.Errorf("expected at least 2 inspections by http plugin, got %d", mockPlugin.inspectedCount.Load())
	}
}

func TestDaemon_HTTPPortRange_ManyToOne(t *testing.T) {
	l1, l2, u1, _ := findTwoPortPairs(t)

	// Single Upstream Server
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response-from-single-target"))
	})}
	lnU, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", u1))
	if err != nil {
		t.Fatalf("failed to listen on single upstream: %v", err)
	}
	go srv.Serve(lnU)
	defer srv.Close()

	cfg := &config.Config{
		Version: "1.0",
		Plugins: config.PluginsConfig{
			Enabled: []string{"http"},
		},
		Services: map[string]config.ServiceConfig{
			"http-many-to-one": {
				Name:     "http-many-to-one",
				Listen:   fmt.Sprintf("127.0.0.1:%d-%d", l1, l2),
				Upstream: fmt.Sprintf("127.0.0.1:%d", u1),
				Protocol: "http",
			},
		},
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("daemon Run exited prematurely: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Query Port 1 -> Should map to Single Upstream
	resp1, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l1))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l1, err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)
	if string(body1) != "response-from-single-target" {
		t.Errorf("port %d expected response from single upstream, got %q", l1, string(body1))
	}

	// 2. Query Port 2 -> Should also map to Single Upstream
	resp2, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l2))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l2, err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "response-from-single-target" {
		t.Errorf("port %d expected response from single upstream, got %q", l2, string(body2))
	}
}


