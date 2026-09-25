package protocol

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// SMTPInspectorOptions configures the SMTP proxy behavior.
type SMTPInspectorOptions struct {
	BlockedSenderDomains []string
	RequireSTARTTLS      bool
	OnAuthFailure        func()
}

// SMTPProxy handles inspection and relaying of an SMTP session.
type SMTPProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     SMTPInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewSMTPProxy creates a new SMTPProxy session.
func NewSMTPProxy(client, upstream net.Conn, opts SMTPInspectorOptions) *SMTPProxy {
	return &SMTPProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the SMTP inspection and proxying loop.
func (p *SMTPProxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	greeting, err := readSMTPResponse(upstreamReader)
	if err != nil {
		return p.result(), true, "failed reading upstream greeting: " + err.Error()
	}
	if err := p.writeClient(greeting); err != nil {
		return p.result(), false, ""
	}

	inAuthExchange := false

	for {
		p.client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return p.result(), false, ""
			}
			return p.result(), false, ""
		}
		p.bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// 1. DATA Handover
		if upper == "DATA" {
			if err := p.writeUpstream(clientLine); err != nil {
				return p.result(), false, ""
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			if err := p.writeClient(resp); err != nil {
				return p.result(), false, ""
			}
			if strings.HasPrefix(strings.TrimSpace(resp), "354") {
				if err := p.relaySMTPData(clientReader, upstreamReader); err != nil {
					return p.result(), false, ""
				}
			}
			continue
		}

		// 2. STARTTLS Handover
		if upper == "STARTTLS" {
			if err := p.writeUpstream(clientLine); err != nil {
				return p.result(), false, ""
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			if err := p.writeClient(resp); err != nil {
				return p.result(), false, ""
			}
			if strings.HasPrefix(strings.TrimSpace(resp), "220") {
				clientBuffered := &BufferedConn{Reader: clientReader, Conn: p.client}
				upstreamBuffered := &BufferedConn{Reader: upstreamReader, Conn: p.upstream}
				res := Proxy(clientBuffered, upstreamBuffered)
				p.bytesIn.Add(res.BytesIn)
				p.bytesOut.Add(res.BytesOut)
				return p.result(), false, ""
			}
			continue
		}

		// 3. Sender domain check
		if strings.HasPrefix(upper, "MAIL FROM:") {
			senderDomain := extractSenderDomain(trimmed[10:])
			if p.isDomainBlocked(senderDomain) {
				p.writeClient("554 5.7.1 Sender domain rejected by RouteWarden\r\n")
				return p.result(), true, fmt.Sprintf("blocked sender domain: %s", senderDomain)
			}
		}

		// 4. AUTH command tracking
		if strings.HasPrefix(upper, "AUTH ") {
			inAuthExchange = true
		}

		// Forward command to upstream
		if err := p.writeUpstream(clientLine); err != nil {
			return p.result(), false, ""
		}

		resp, err := readSMTPResponse(upstreamReader)
		if err != nil {
			return p.result(), false, ""
		}

		// Check auth result
		if inAuthExchange {
			respTrimmed := strings.TrimSpace(resp)
			if strings.HasPrefix(respTrimmed, "535") || strings.HasPrefix(respTrimmed, "504") || strings.HasPrefix(respTrimmed, "501") {
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
				inAuthExchange = false
			} else if strings.HasPrefix(respTrimmed, "235") {
				inAuthExchange = false
			} else if !strings.HasPrefix(respTrimmed, "334") {
				inAuthExchange = false
			}
		}

		if err := p.writeClient(resp); err != nil {
			return p.result(), false, ""
		}

		if upper == "QUIT" {
			return p.result(), false, ""
		}
	}
}

func (p *SMTPProxy) relaySMTPData(clientReader *bufio.Reader, upstreamReader *bufio.Reader) error {
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			return err
		}
		p.bytesIn.Add(int64(len(line)))
		if err := p.writeUpstream(line); err != nil {
			return err
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
	}
	resp, err := readSMTPResponse(upstreamReader)
	if err != nil {
		return err
	}
	return p.writeClient(resp)
}

func (p *SMTPProxy) writeClient(s string) error {
	b := []byte(s)
	p.bytesOut.Add(int64(len(b)))
	_, err := p.client.Write(b)
	return err
}

func (p *SMTPProxy) writeUpstream(s string) error {
	_, err := p.upstream.Write([]byte(s))
	return err
}

func (p *SMTPProxy) isDomainBlocked(domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	for _, pattern := range p.opts.BlockedSenderDomains {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			base := strings.TrimPrefix(pattern, "*.")
			if domain == base || strings.HasSuffix(domain, "."+base) {
				return true
			}
		}
		if matched, _ := filepath.Match(pattern, domain); matched {
			return true
		}
	}
	return false
}

func extractSenderDomain(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, ">"); idx != -1 {
		addr = addr[:idx]
	}
	if idx := strings.LastIndex(addr, "@"); idx != -1 {
		return strings.ToLower(strings.TrimSpace(addr[idx+1:]))
	}
	return ""
}

func readSMTPResponse(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) >= 4 && (trimmed[3] == ' ' || len(trimmed) == 3) {
			break
		}
		if len(trimmed) < 4 {
			break
		}
	}
	return sb.String(), nil
}

func (p *SMTPProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}
