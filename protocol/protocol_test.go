package protocol

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type mockCloseWriterConn struct {
	net.Conn
	closedWrite bool
}

func (m *mockCloseWriterConn) CloseWrite() error {
	m.closedWrite = true
	return nil
}

func TestProxy(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	// Run proxy in background
	proxyDone := make(chan ProxyResult, 1)
	go func() {
		proxyDone <- Proxy(proxyClient, proxyUpstream)
	}()

	// Client sends data, upstream echoes back
	clientPayload := []byte("hello from client")
	upstreamPayload := []byte("hello from upstream")

	go func() {
		buf := make([]byte, len(clientPayload))
		_, _ = io.ReadFull(upstreamConn, buf)
		_, _ = upstreamConn.Write(upstreamPayload)
		_ = upstreamConn.Close()
	}()

	go func() {
		_, _ = clientConn.Write(clientPayload)
		buf := make([]byte, len(upstreamPayload))
		_, _ = io.ReadFull(clientConn, buf)
		_ = clientConn.Close()
	}()

	res := <-proxyDone
	if res.BytesIn != int64(len(clientPayload)) {
		t.Errorf("expected BytesIn=%d, got %d", len(clientPayload), res.BytesIn)
	}
	if res.BytesOut != int64(len(upstreamPayload)) {
		t.Errorf("expected BytesOut=%d, got %d", len(upstreamPayload), res.BytesOut)
	}
}

func TestBufferedConn_Read(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	peeked := []byte("peeked-prefix:")
	buffered := &BufferedConn{
		Reader: io.MultiReader(bytes.NewReader(peeked), c1),
		Conn:   c1,
	}

	go func() {
		_, _ = c2.Write([]byte("stream-body"))
	}()

	buf := make([]byte, len(peeked)+len("stream-body"))
	_, err := io.ReadFull(buffered, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}

	expected := "peeked-prefix:stream-body"
	if string(buf) != expected {
		t.Errorf("expected %q, got %q", expected, string(buf))
	}
}

func TestBufferedConn_CloseWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	mock := &mockCloseWriterConn{Conn: c1}
	bConn := &BufferedConn{
		Reader: c1,
		Conn:   mock,
	}

	if err := bConn.CloseWrite(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.closedWrite {
		t.Errorf("expected CloseWrite to be forwarded to mockCloseWriterConn")
	}
}

// ── Bug #12 (Round 2): Proxy half-close must not call dst.Close() ──

func TestProxy_HalfCloseNoCloseWriter(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan ProxyResult, 1)
	go func() {
		done <- Proxy(proxyClient, proxyUpstream)
	}()

	clientMsg := []byte("ping")
	upstreamResponse := []byte("pong response from upstream server")

	go func() {
		// Read client ping, then close read on clientConn
		buf := make([]byte, len(clientMsg))
		_, _ = io.ReadFull(upstreamConn, buf)

		// Wait briefly to simulate server processing time while client side is closing
		time.Sleep(20 * time.Millisecond)

		// Write response back to client
		_, _ = upstreamConn.Write(upstreamResponse)
		_ = upstreamConn.Close()
	}()

	// Client writes ping and then closes its connection to trigger half-close in proxy
	_, _ = clientConn.Write(clientMsg)

	// In the old buggy code, clientConn's finish triggered proxyUpstream.Close(),
	// terminating upstreamConn before it could send its response.
	readBuf := make([]byte, len(upstreamResponse))
	_, err := io.ReadFull(clientConn, readBuf)
	if err != nil {
		t.Fatalf("failed to read response from upstream through proxy: %v", err)
	}
	_ = clientConn.Close()

	if !bytes.Equal(readBuf, upstreamResponse) {
		t.Errorf("expected %q, got %q", string(upstreamResponse), string(readBuf))
	}

	select {
	case res := <-done:
		if res.BytesIn != int64(len(clientMsg)) {
			t.Errorf("expected BytesIn=%d, got %d", len(clientMsg), res.BytesIn)
		}
		if res.BytesOut != int64(len(upstreamResponse)) {
			t.Errorf("expected BytesOut=%d, got %d", len(upstreamResponse), res.BytesOut)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy timed out waiting for completion")
	}
}
