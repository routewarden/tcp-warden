package protocol

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

// ProxyResult is returned by a proxy session when it completes.
type ProxyResult struct {
	BytesIn  int64
	BytesOut int64
	Err      error
}

// Proxy performs a bidirectional io.Copy between client and upstream.
// It blocks until both directions are done and returns byte counts.
func Proxy(client, upstream net.Conn) ProxyResult {
	var bytesIn, bytesOut atomic.Int64
	done := make(chan struct{}, 2)

	type closeWriter interface {
		CloseWrite() error
	}

	copy := func(dst, src net.Conn, counter *atomic.Int64) {
		n, _ := io.Copy(dst, src)
		counter.Add(n)
		// Half-close: signal EOF to the other side
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}

	go copy(upstream, client, &bytesIn)
	go copy(client, upstream, &bytesOut)

	<-done
	<-done

	return ProxyResult{
		BytesIn:  bytesIn.Load(),
		BytesOut: bytesOut.Load(),
	}
}

// DialUpstream opens a TCP connection to the upstream address with a reasonable timeout.
func DialUpstream(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

// BufferedConn wraps a reader and a net.Conn so that peeked or buffered
// bytes can be seamlessly read before reading from the underlying conn.
type BufferedConn struct {
	io.Reader
	net.Conn
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.Reader.Read(p)
}

// CloseWrite forwards half-close to the underlying Conn if supported.
func (b *BufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
