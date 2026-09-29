package protocol

import (
	"bytes"
	"io"
	"net"
	"testing"
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
