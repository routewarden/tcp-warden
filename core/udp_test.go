package core

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/config"
)

// ── UDPSessionTable tests ─────────────────────────────────────────────────────

func TestUDPSessionTable_GetOrCreate_NewSession(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	called := 0

	sess, isNew, err := table.GetOrCreate("1.2.3.4:5000", func() (*UDPSession, error) {
		called++
		c, _ := udpTestConn()
		return &UDPSession{ClientAddr: addr, Upstream: c}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Fatal("expected isNew=true for first creation")
	}
	if called != 1 {
		t.Fatalf("create func called %d times, want 1", called)
	}
	_ = sess
}

func TestUDPSessionTable_GetOrCreate_ExistingSession(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	createCount := 0
	create := func() (*UDPSession, error) {
		createCount++
		c, _ := udpTestConn()
		return &UDPSession{ClientAddr: addr, Upstream: c}, nil
	}

	_, isNew1, _ := table.GetOrCreate("1.2.3.4:5000", create)
	_, isNew2, _ := table.GetOrCreate("1.2.3.4:5000", create)

	if !isNew1 {
		t.Error("first call: expected isNew=true")
	}
	if isNew2 {
		t.Error("second call: expected isNew=false (session already exists)")
	}
	if createCount != 1 {
		t.Errorf("create func called %d times, want 1", createCount)
	}
}

func TestUDPSessionTable_GetOrCreate_CreateError(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	_, _, err := table.GetOrCreate("bad:0", func() (*UDPSession, error) {
		return nil, fmt.Errorf("upstream unreachable")
	})

	if err == nil {
		t.Fatal("expected error from create func, got nil")
	}
}

func TestUDPSessionTable_Delete(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 9999}
	c, _ := udpTestConn()
	sess := &UDPSession{ClientAddr: addr, Upstream: c}
	table.sessions.Store("5.6.7.8:9999", sess)

	table.Delete("5.6.7.8:9999")

	if _, ok := table.sessions.Load("5.6.7.8:9999"); ok {
		t.Error("session still present after Delete")
	}
}

func TestUDPSessionTable_Len(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	if got := table.Len(); got != 0 {
		t.Fatalf("empty table Len()=%d, want 0", got)
	}

	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("10.0.0.%d:1000", i)
		addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("10.0.0.%d", i)), Port: 1000}
		c, _ := udpTestConn()
		table.sessions.Store(key, &UDPSession{ClientAddr: addr, Upstream: c})
	}

	if got := table.Len(); got != 3 {
		t.Fatalf("Len()=%d, want 3", got)
	}
}

func TestUDPSessionTable_Reaper(t *testing.T) {
	timeout := 200 * time.Millisecond
	table := NewUDPSessionTable(timeout)
	// Don't defer table.Close() here — we want the reaper goroutine to do the work.

	addr := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222}
	c, _ := udpTestConn()
	// Stamp as already expired.
	sess := &UDPSession{ClientAddr: addr, Upstream: c, lastSeen: time.Now().Add(-timeout - time.Second)}
	table.sessions.Store("2.2.2.2:2222", sess)

	// Reaper fires at timeout/2 = 100ms; wait long enough for two cycles.
	time.Sleep(timeout + 150*time.Millisecond)

	if _, ok := table.sessions.Load("2.2.2.2:2222"); ok {
		t.Error("expected idle session to be reaped, but it still exists")
	}
	table.Close()
}

// ── UDPSession Touch / isIdle tests ──────────────────────────────────────────

func TestUDPSession_Touch_ResetsIdleTimer(t *testing.T) {
	c, _ := udpTestConn()
	sess := &UDPSession{
		Upstream: c,
		lastSeen: time.Now().Add(-10 * time.Second),
	}

	// Without Touch, the session is idle.
	if !sess.isIdle(5 * time.Second) {
		t.Fatal("expected session to be idle before Touch")
	}
	sess.Touch()
	if sess.isIdle(5 * time.Second) {
		t.Fatal("expected session to be non-idle after Touch")
	}
}

// ── UDP engine end-to-end smoke test ─────────────────────────────────────────

// TestUDPEngine_ForwardPacket wires up a real loopback UDP socket pair and
// verifies that handleUDPPacket delivers the payload to an upstream echo server
// and the reply makes it back to the client.
func TestUDPEngine_ForwardPacket(t *testing.T) {
	// 1. Start a simple UDP echo server as the "upstream".
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("echo ListenUDP: %v", err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], src)
		}
	}()

	// 2. Build a minimal Daemon.
	cfg := &config.Config{
		Version: "1.0",
		Global:  config.GlobalConfig{},
		Services: map[string]config.ServiceConfig{
			"udp-test": {
				Name:      "udp-test",
				Transport: "udp",
				Upstream:  echoAddr.String(),
			},
		},
	}
	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()
	oplog := NewLogger(LevelWarn, nil)
	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)

	d := &Daemon{
		cfg:      cfg,
		banlist:  bl,
		failures: ft,
		limiter:  rl,
		stats:    stats,
		bus:      bus,
		pipeline: pipe,
		oplog:    oplog,
	}

	// 3. Open the shared listen socket (the "warden" side).
	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen ListenUDP: %v", err)
	}
	defer listenConn.Close()

	// 4. Open a real client socket so the "WriteTo(clientAddr)" reply goes somewhere.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	defer clientConn.Close()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	svc := cfg.Services["udp-test"]
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	// 5. Wait for the reply on the real client socket.
	replyCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := clientConn.ReadFromUDP(buf)
		if err == nil {
			replyCh <- buf[:n]
		} else {
			replyCh <- nil
		}
	}()

	payload := []byte("hello-udp-engine")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	d.handleUDPPacket(ctx, listenConn, clientAddr, payload, svc, table)

	reply := <-replyCh
	if string(reply) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", reply, payload)
	}
}

// ── MaxSessions guard test ────────────────────────────────────────────────────

func TestUDPEngine_MaxSessions(t *testing.T) {
	echoConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = src
			_ = n
		}
	}()

	cfg := &config.Config{
		Version: "1.0",
		Services: map[string]config.ServiceConfig{
			"udp-max": {
				Name:      "udp-max",
				Transport: "udp",
				Upstream:  echoAddr.String(),
				UDP:       config.UDPConfig{MaxSessions: 1}, // allow only 1
			},
		},
	}
	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()
	oplog := NewLogger(LevelWarn, nil)
	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)

	d := &Daemon{
		cfg:      cfg,
		banlist:  bl,
		failures: ft,
		limiter:  rl,
		stats:    stats,
		bus:      bus,
		pipeline: pipe,
		oplog:    oplog,
	}

	listenConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer listenConn.Close()

	svc := cfg.Services["udp-max"]
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()
	ctx := context.Background()

	// Pre-fill the session table to reach MaxSessions.
	fakeAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111}
	fakeConn, _ := udpTestConn()
	table.sessions.Store(fakeAddr.String(), &UDPSession{ClientAddr: fakeAddr, Upstream: fakeConn, lastSeen: time.Now()})

	// Now a second client should be blocked.
	secondClient := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2222}
	d.handleUDPPacket(ctx, listenConn, secondClient, []byte("blocked"), svc, table)

	// Verify the second client did NOT create a session.
	if _, ok := table.sessions.Load(secondClient.String()); ok {
		t.Error("second client session was created despite MaxSessions=1")
	}

	// Verify the second client's packet was counted as blocked.
	snap := stats.GetOrCreate("udp-max").Snapshot()
	if snap.BlockedConnections == 0 {
		t.Error("expected BlockedConnections > 0 after MaxSessions exceeded")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// udpTestConn creates a throwaway UDP listen socket for use as a fake Upstream in tests.
func udpTestConn() (*net.UDPConn, func()) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("udpTestConn: %v", err))
	}
	return conn, func() { conn.Close() }
}
