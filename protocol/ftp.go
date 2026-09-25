package protocol

import (
	"bufio"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// FTPInspectorOptions configures FTP authentication inspection.
type FTPInspectorOptions struct {
	OnAuthFailure func()
}

// FTPProxy inspects and relays FTP wire sessions (RFC 959).
type FTPProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     FTPInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewFTPProxy creates a new FTPProxy session.
func NewFTPProxy(client, upstream net.Conn, opts FTPInspectorOptions) *FTPProxy {
	return &FTPProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the FTP inspection and relay loop.
func (p *FTPProxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	// 1. Read upstream server greeting (may be multi-line: 220- ...)
	greeting, err := readFTPResponse(upstreamReader)
	if err != nil {
		return p.result(), true, "failed reading FTP greeting: " + err.Error()
	}
	p.bytesOut.Add(int64(len(greeting)))
	if _, err := p.client.Write([]byte(greeting)); err != nil {
		return p.result(), false, ""
	}

	for {
		p.client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// Forward command to upstream
		p.upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := p.upstream.Write([]byte(clientLine)); err != nil {
			return p.result(), false, ""
		}

		// Read upstream response
		p.upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		serverResp, err := readFTPResponse(upstreamReader)
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(int64(len(serverResp)))

		// Check for AUTH TLS / AUTH SSL handover
		if strings.HasPrefix(upper, "AUTH TLS") || strings.HasPrefix(upper, "AUTH SSL") {
			if _, err := p.client.Write([]byte(serverResp)); err != nil {
				return p.result(), false, ""
			}
			if strings.HasPrefix(serverResp, "234") {
				// Switch to raw bidirectional TLS proxy
				p.client.SetDeadline(time.Time{})
				p.upstream.SetDeadline(time.Time{})
				proxyRes := Proxy(p.client, p.upstream)
				p.bytesIn.Add(proxyRes.BytesIn)
				p.bytesOut.Add(proxyRes.BytesOut)
				return p.result(), false, ""
			}
			continue
		}

		// Check for authentication failure on PASS command
		if strings.HasPrefix(upper, "PASS ") || upper == "PASS" {
			if strings.HasPrefix(serverResp, "530") {
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
		}

		// Forward upstream response to client
		p.client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := p.client.Write([]byte(serverResp)); err != nil {
			return p.result(), false, ""
		}

		// QUIT command terminates session
		if upper == "QUIT" {
			return p.result(), false, ""
		}
	}
}

func (p *FTPProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}

// readFTPResponse reads a possibly multi-line FTP response (e.g. 220- ... 220 OK).
func readFTPResponse(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' && isDigit(line[0]) && isDigit(line[1]) && isDigit(line[2]) {
			break
		}
	}
	return sb.String(), nil
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
