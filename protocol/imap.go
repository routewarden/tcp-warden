package protocol

import (
	"bufio"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// IMAPInspectorOptions configures the IMAP proxy inspector.
type IMAPInspectorOptions struct {
	OnAuthFailure func()
}

// IMAPProxy handles inspection and relaying of an IMAP session.
type IMAPProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     IMAPInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewIMAPProxy creates a new IMAPProxy session.
func NewIMAPProxy(client, upstream net.Conn, opts IMAPInspectorOptions) *IMAPProxy {
	return &IMAPProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the IMAP inspection and relay loop.
func (p *IMAPProxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	greeting, err := upstreamReader.ReadString('\n')
	if err != nil {
		return p.result(), true, "failed reading IMAP greeting: " + err.Error()
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

		parts := strings.Fields(strings.TrimSpace(clientLine))
		tag := ""
		cmd := ""
		if len(parts) >= 2 {
			tag = parts[0]
			cmd = strings.ToUpper(parts[1])
		}

		// STARTTLS Handover
		if cmd == "STARTTLS" {
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
			if strings.Contains(strings.ToUpper(resp), "OK") {
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

		// Read responses until tagged completion response
		for {
			resp, err := upstreamReader.ReadString('\n')
			if err != nil {
				return p.result(), false, ""
			}
			p.bytesOut.Add(int64(len(resp)))
			if _, err := p.client.Write([]byte(resp)); err != nil {
				return p.result(), false, ""
			}

			trimmedResp := strings.TrimSpace(resp)
			respParts := strings.Fields(trimmedResp)

			if tag != "" && len(respParts) >= 2 && respParts[0] == tag {
				status := strings.ToUpper(respParts[1])
				if (cmd == "LOGIN" || cmd == "AUTHENTICATE") && (status == "NO" || status == "BAD") {
					if p.opts.OnAuthFailure != nil {
						p.opts.OnAuthFailure()
					}
				}
				break
			}

			// Continuation or untagged response continues
			if tag == "" || (!strings.HasPrefix(trimmedResp, "*") && !strings.HasPrefix(trimmedResp, "+")) {
				break
			}
		}

		if cmd == "LOGOUT" {
			return p.result(), false, ""
		}
	}
}

func (p *IMAPProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}
