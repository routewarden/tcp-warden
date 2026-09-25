package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSSHInspector(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		clientConn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
	}()

	inspector := SSHInspector{}
	r, res := inspector.Inspect(serverConn)
	if !res.Valid {
		t.Fatalf("expected valid SSH-2.0, got invalid")
	}
	if res.ClientVersion != "SSH-2.0-OpenSSH_9.0" {
		t.Errorf("expected SSH-2.0-OpenSSH_9.0, got %q", res.ClientVersion)
	}
	if res.IsSSH1 {
		t.Errorf("expected IsSSH1=false")
	}
	_ = r
}

func TestSSHInspectorRejectSSH1(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		clientConn.Write([]byte("SSH-1.5-OpenSSH_1.0\r\n"))
	}()

	inspector := SSHInspector{}
	_, res := inspector.Inspect(serverConn)
	if !res.IsSSH1 {
		t.Errorf("expected IsSSH1=true for SSH-1.5")
	}
}

func TestSSHAuthMonitor(t *testing.T) {
	var failures int
	var mu sync.Mutex
	monitor := NewSSHAuthMonitor(func() {
		mu.Lock()
		failures++
		mu.Unlock()
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	wrapped := monitor.WrapUpstream(clientConn)

	// Simulate an SSH_MSG_USERAUTH_FAILURE packet (packet_length=12, padding_length=10, type=51)
	pkt := []byte{
		0x00, 0x00, 0x00, 0x0c, // length = 12
		0x0a,                   // padding = 10
		0x33,                   // msg_type = 51 (SSH_MSG_USERAUTH_FAILURE)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding bytes
	}

	go func() {
		serverConn.Write(pkt)
	}()

	buf := make([]byte, 64)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if n != len(pkt) {
		t.Errorf("expected %d bytes, got %d", len(pkt), n)
	}

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if failures != 1 {
		t.Errorf("expected 1 auth failure detected, got %d", failures)
	}
	mu.Unlock()
}

func TestSMTPProxyBlockedDomain(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	// Upstream sends greeting
	go func() {
		upstreamConn.Write([]byte("220 mail.example.com ESMTP Postfix\r\n"))
	}()

	opts := SMTPInspectorOptions{
		BlockedSenderDomains: []string{"*.spammer.com", "evil.org"},
	}
	proxy := NewSMTPProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		// Read greeting
		buf := make([]byte, 128)
		clientConn.Read(buf)

		// Send MAIL FROM with blocked domain
		clientConn.Write([]byte("MAIL FROM:<bad@spammer.com>\r\n"))

		// Read 554 response from proxy
		clientConn.Read(buf)
	}()

	res, wasBlocked, reason := proxy.Run()
	_ = res
	if !wasBlocked {
		t.Fatalf("expected blocked sender domain, got allowed")
	}
	if !strings.Contains(reason, "blocked sender domain") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestPOP3ProxyAuthFailure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	var authFailures int
	opts := POP3InspectorOptions{
		OnAuthFailure: func() {
			authFailures++
		},
	}
	proxy := NewPOP3Proxy(proxyClientConn, proxyUpstreamConn, opts)

	// Upstream greeting & responses
	go func() {
		upstreamConn.Write([]byte("+OK Dovecot ready.\r\n"))

		buf := make([]byte, 128)
		upstreamConn.Read(buf) // USER
		upstreamConn.Write([]byte("+OK\r\n"))

		upstreamConn.Read(buf) // PASS
		upstreamConn.Write([]byte("-ERR Authentication failed.\r\n"))

		upstreamConn.Read(buf) // QUIT
		upstreamConn.Write([]byte("+OK Logging out.\r\n"))
	}()

	go func() {
		buf := make([]byte, 128)
		clientConn.Read(buf) // greeting

		clientConn.Write([]byte("USER victim\r\n"))
		clientConn.Read(buf)

		clientConn.Write([]byte("PASS wrongpass\r\n"))
		clientConn.Read(buf)

		clientConn.Write([]byte("QUIT\r\n"))
		clientConn.Read(buf)
		clientConn.Close()
	}()

	proxy.Run()
	if authFailures != 1 {
		t.Errorf("expected 1 POP3 auth failure, got %d", authFailures)
	}
}

func TestIMAPProxyAuthFailure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	var authFailures int
	opts := IMAPInspectorOptions{
		OnAuthFailure: func() {
			authFailures++
		},
	}
	proxy := NewIMAPProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		upstreamConn.Write([]byte("* OK IMAP4rev1 Service Ready\r\n"))

		buf := make([]byte, 256)
		upstreamConn.Read(buf) // A01 LOGIN victim wrongpass
		upstreamConn.Write([]byte("A01 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"))

		upstreamConn.Read(buf) // A02 LOGOUT
		upstreamConn.Write([]byte("* BYE Logging out\r\nA02 OK Logout completed\r\n"))
	}()

	go func() {
		buf := make([]byte, 256)
		clientConn.Read(buf) // greeting

		clientConn.Write([]byte("A01 LOGIN victim wrongpass\r\n"))
		clientConn.Read(buf)

		clientConn.Write([]byte("A02 LOGOUT\r\n"))
		clientConn.Read(buf)
		clientConn.Close()
	}()

	proxy.Run()
	if authFailures != 1 {
		t.Errorf("expected 1 IMAP auth failure, got %d", authFailures)
	}
}

func TestBuildSSHDisconnect(t *testing.T) {
	msg := buildSSHDisconnect(11, "Too many authentication failures")
	if len(msg) < 16 {
		t.Fatalf("SSH disconnect message too short: %d bytes", len(msg))
	}
	// Verify padding alignment to 8 bytes
	pktLen := int(msg[0])<<24 | int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if (pktLen+4)%8 != 0 {
		t.Errorf("SSH packet length %d (+4) not 8-byte aligned", pktLen)
	}
	if msg[5] != 1 { // SSH_MSG_DISCONNECT
		t.Errorf("expected message type 1, got %d", msg[5])
	}
	if !bytes.Contains(msg, []byte("Too many authentication failures")) {
		t.Errorf("disconnect packet does not contain reason message")
	}
}

func TestPostgresProxyAuthFailure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	var authFailures int
	opts := PostgresInspectorOptions{
		OnAuthFailure: func() {
			authFailures++
		},
	}
	proxy := NewPostgresProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		// 1. Read startup message from client
		var lenBuf [4]byte
		io.ReadFull(upstreamConn, lenBuf[:])
		sLen := binary.BigEndian.Uint32(lenBuf[:])
		payload := make([]byte, sLen-4)
		io.ReadFull(upstreamConn, payload)

		// 2. Send AuthenticationRequest (Cleartext = 3)
		upstreamConn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})

		// 3. Read password response from client ('p', 4-byte len, payload)
		var pType [1]byte
		io.ReadFull(upstreamConn, pType[:])
		var pLenBuf [4]byte
		io.ReadFull(upstreamConn, pLenBuf[:])
		pLen := binary.BigEndian.Uint32(pLenBuf[:])
		pBody := make([]byte, pLen-4)
		io.ReadFull(upstreamConn, pBody)

		// 4. Send ErrorResponse with Code '28P01' (invalid password)
		errPayload := []byte("SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
		eLen := uint32(4 + len(errPayload))
		eHeader := []byte{'E', byte(eLen >> 24), byte(eLen >> 16), byte(eLen >> 8), byte(eLen)}
		upstreamConn.Write(append(eHeader, errPayload...))
		upstreamConn.Close()
	}()

	go func() {
		// Send StartupMessage: length 4 + 13 bytes, version 196608 (4 bytes), "user\0pg\0\0"
		startupPayload := []byte{0, 3, 0, 0, 'u', 's', 'e', 'r', 0, 'p', 'g', 0, 0}
		sLen := uint32(4 + len(startupPayload))
		sHeader := []byte{byte(sLen >> 24), byte(sLen >> 16), byte(sLen >> 8), byte(sLen)}
		clientConn.Write(append(sHeader, startupPayload...))

		// Read AuthRequest ('R' 8 bytes)
		var rType [1]byte
		io.ReadFull(clientConn, rType[:])
		var rLenBuf [4]byte
		io.ReadFull(clientConn, rLenBuf[:])
		rLen := binary.BigEndian.Uint32(rLenBuf[:])
		rBody := make([]byte, rLen-4)
		io.ReadFull(clientConn, rBody)

		// Send password: 'p', length 4 + 7, "secret\0"
		pwd := []byte{'p', 0, 0, 0, 11, 's', 'e', 'c', 'r', 'e', 't', 0}
		clientConn.Write(pwd)

		// Read ErrorResponse
		var eType [1]byte
		io.ReadFull(clientConn, eType[:])
		var eLenBuf [4]byte
		io.ReadFull(clientConn, eLenBuf[:])
		eLen := binary.BigEndian.Uint32(eLenBuf[:])
		eBody := make([]byte, eLen-4)
		io.ReadFull(clientConn, eBody)
		clientConn.Close()
	}()

	proxy.Run()
	if authFailures != 1 {
		t.Errorf("expected 1 Postgres auth failure, got %d", authFailures)
	}
}

func TestMySQLProxyAuthFailure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	var authFailures int
	opts := MySQLInspectorOptions{
		OnAuthFailure: func() {
			authFailures++
		},
	}
	proxy := NewMySQLProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		// 1. Send Handshake packet (seq 0)
		hsPayload := []byte{10, '5', '.', '7', 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		hsPkt := append([]byte{byte(len(hsPayload)), 0, 0, 0}, hsPayload...)
		upstreamConn.Write(hsPkt)

		// 2. Read client HandshakeResponse (seq 1)
		hdr := make([]byte, 4)
		upstreamConn.Read(hdr)
		cLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, cLen)
		upstreamConn.Read(body)

		// 3. Send ERR packet (seq 2) with error code 1045 (0x15 0x04)
		errPayload := []byte{0xFF, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'A', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}
		errPkt := append([]byte{byte(len(errPayload)), 0, 0, 2}, errPayload...)
		upstreamConn.Write(errPkt)
	}()

	go func() {
		// Read handshake
		buf := make([]byte, 128)
		clientConn.Read(buf)

		// Send client response (capabilities without SSL)
		cResp := []byte{0x00, 0x02, 0x00, 0x00, 'r', 'o', 'o', 't', 0, 0}
		cPkt := append([]byte{byte(len(cResp)), 0, 0, 1}, cResp...)
		clientConn.Write(cPkt)

		// Read ERR response
		clientConn.Read(buf)
		clientConn.Close()
	}()

	proxy.Run()
	if authFailures != 1 {
		t.Errorf("expected 1 MySQL auth failure, got %d", authFailures)
	}
}

func TestRedisProxyAuthFailure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	var authFailures int
	opts := RedisInspectorOptions{
		OnAuthFailure: func() {
			authFailures++
		},
	}
	proxy := NewRedisProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		// Read AUTH command from client
		buf := make([]byte, 128)
		upstreamConn.Read(buf)

		// Return -WRONGPASS error
		upstreamConn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
	}()

	go func() {
		// Send AUTH
		clientConn.Write([]byte("AUTH wrongpassword\r\n"))
		buf := make([]byte, 128)
		clientConn.Read(buf)
		clientConn.Close()
	}()

	proxy.Run()
	if authFailures != 1 {
		t.Errorf("expected 1 Redis auth failure, got %d", authFailures)
	}
}

func TestRedisProxyBlockedCommand(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	opts := RedisInspectorOptions{
		BlockedCommands: []string{"FLUSHALL", "KEYS"},
	}
	proxy := NewRedisProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		// Client sends blocked FLUSHALL
		clientConn.Write([]byte("FLUSHALL\r\n"))
		buf := make([]byte, 128)
		n, _ := clientConn.Read(buf)
		resp := string(buf[:n])
		if !strings.Contains(resp, "is blocked by RouteWarden") {
			t.Errorf("expected blocked command error, got %q", resp)
		}
		clientConn.Close()
	}()

	_, wasBlocked, reason := proxy.Run()
	if !wasBlocked {
		t.Errorf("expected wasBlocked=true")
	}
	if !strings.Contains(reason, "FLUSHALL") {
		t.Errorf("expected reason to contain FLUSHALL, got %q", reason)
	}
}

func TestFTPProxyAuthFailure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	var authFailures int
	opts := FTPInspectorOptions{
		OnAuthFailure: func() {
			authFailures++
		},
	}
	proxy := NewFTPProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		// 1. Send greeting
		upstreamConn.Write([]byte("220 Service ready.\r\n"))

		buf := make([]byte, 128)
		// 2. Read USER
		upstreamConn.Read(buf)
		upstreamConn.Write([]byte("331 User name okay, need password.\r\n"))

		// 3. Read PASS
		upstreamConn.Read(buf)
		upstreamConn.Write([]byte("530 Login incorrect.\r\n"))
	}()

	go func() {
		buf := make([]byte, 128)
		clientConn.Read(buf) // greeting

		clientConn.Write([]byte("USER anonymous\r\n"))
		clientConn.Read(buf) // 331

		clientConn.Write([]byte("PASS wrongpass\r\n"))
		clientConn.Read(buf) // 530
		clientConn.Close()
	}()

	proxy.Run()
	if authFailures != 1 {
		t.Errorf("expected 1 FTP auth failure, got %d", authFailures)
	}
}

func TestTLSSNIProxyAllowedAndBlocked(t *testing.T) {
	// Build a valid TLS 1.2 ClientHello with SNI "evil.malicious.org"
	sni := "evil.malicious.org"
	sniBytes := []byte(sni)

	// Extension data
	extData := []byte{
		0, byte(len(sniBytes) + 3), // list len
		0,                          // host_name type
		0, byte(len(sniBytes)),     // name len
	}
	extData = append(extData, sniBytes...)

	// Extension header: type 0x0000 (2 bytes), len (2 bytes)
	ext := []byte{0, 0, 0, byte(len(extData))}
	ext = append(ext, extData...)

	// Extensions block
	extsBlock := []byte{0, byte(len(ext))}
	extsBlock = append(extsBlock, ext...)

	// ClientHello body: version(2) + random(32) + sessionID(1=0) + ciphers(2+2) + comp(1+1)
	chBody := []byte{0x03, 0x03}
	chBody = append(chBody, make([]byte, 32)...) // random
	chBody = append(chBody, 0)                   // session ID len
	chBody = append(chBody, 0, 2, 0x00, 0x9c)    // ciphers len 2 + TLS_RSA_WITH_AES_128_GCM_SHA256
	chBody = append(chBody, 1, 0)                // comp len 1, no comp
	chBody = append(chBody, extsBlock...)

	// Handshake header: type 1 (ClientHello) + 3 bytes len
	chLen := len(chBody)
	hs := []byte{1, byte(chLen >> 16), byte(chLen >> 8), byte(chLen)}
	hs = append(hs, chBody...)

	// TLS Record header: type 0x16 (Handshake) + version 0x0301 + 2 bytes len
	recLen := len(hs)
	record := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	fullTLS := append(record, hs...)

	// Test blocked domain
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyUpstreamConn.Close()
	defer upstreamConn.Close()

	opts := TLSInspectorOptions{
		BlockedDomains: []string{"*.malicious.org"},
	}
	proxy := NewTLSSNIProxy(proxyClientConn, proxyUpstreamConn, opts)

	go func() {
		clientConn.Write(fullTLS)
		clientConn.Close()
	}()

	_, wasBlocked, reason := proxy.Run()
	if !wasBlocked {
		t.Errorf("expected TLS SNI to be blocked")
	}
	if !strings.Contains(reason, "evil.malicious.org") {
		t.Errorf("expected reason to contain SNI, got %q", reason)
	}
}

