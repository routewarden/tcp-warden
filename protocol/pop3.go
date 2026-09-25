package protocol

import (
	"bufio"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// POP3InspectorOptions configures the POP3 proxy inspector.
type POP3InspectorOptions struct {
	OnAuthFailure func()
}

// POP3Proxy handles inspection and relaying of a POP3 session.
type POP3Proxy struct {
	client   net.Conn
	upstream net.Conn
	opts     POP3InspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewPOP3Proxy creates a new POP3Proxy session.
func NewPOP3Proxy(client, upstream net.Conn, opts POP3InspectorOptions) *POP3Proxy {
	return &POP3Proxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the POP3 inspection and relay loop.
func (p *POP3Proxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	greeting, err := upstreamReader.ReadString('\n')
	if err != nil {
		return p.result(), true, "failed reading POP3 greeting: " + err.Error()
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

		// STLS Handover
		if upper == "STLS" {
			if _, err := p.upstream.Write([]byte(clientLine)); err != nil {
				return p.result(), false, ""
			}
			resp, err := upstreamReader.ReadString('\n')
			if err != nil {
				return p.result(), false, ""
			}
			p.bytesOut.Add(int64(len(resp)))
			if _, err := p.client.Write([]byte(resp)); err != nil {
				return p.result(), false, ""
			}
			if strings.HasPrefix(strings.TrimSpace(resp), "+OK") {
				clientBuffered := &BufferedConn{Reader: clientReader, Conn: p.client}
				upstreamBuffered := &BufferedConn{Reader: upstreamReader, Conn: p.upstream}
				res := Proxy(clientBuffered, upstreamBuffered)
				p.bytesIn.Add(res.BytesIn)
				p.bytesOut.Add(res.BytesOut)
				return p.result(), false, ""
			}
			continue
		}

		if _, err := p.upstream.Write([]byte(clientLine)); err != nil {
			return p.result(), false, ""
		}

		// Read response
		isMultiLine := upper == "LIST" || upper == "UIDL" || strings.HasPrefix(upper, "RETR ") || strings.HasPrefix(upper, "TOP ") || upper == "CAPA"
		isSingleArg := strings.HasPrefix(upper, "LIST ") || strings.HasPrefix(upper, "UIDL ")
		if isSingleArg {
			isMultiLine = false
		}

		resp, err := upstreamReader.ReadString('\n')
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(int64(len(resp)))
		if _, err := p.client.Write([]byte(resp)); err != nil {
			return p.result(), false, ""
		}

		trimmedResp := strings.TrimSpace(resp)

		// Check auth failure
		if strings.HasPrefix(upper, "PASS ") || strings.HasPrefix(upper, "AUTH ") {
			if strings.HasPrefix(trimmedResp, "-ERR") {
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
		}

		// Multi-line data relay (terminated by dot-CRLF)
		if isMultiLine && strings.HasPrefix(trimmedResp, "+OK") {
			for {
				line, err := upstreamReader.ReadString('\n')
				if err != nil {
					return p.result(), false, ""
				}
				p.bytesOut.Add(int64(len(line)))
				if _, err := p.client.Write([]byte(line)); err != nil {
					return p.result(), false, ""
				}
				if line == ".\r\n" || line == ".\n" {
					break
				}
			}
		}

		if upper == "QUIT" {
			return p.result(), false, ""
		}
	}
}

func (p *POP3Proxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}
