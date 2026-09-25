package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// PostgresInspectorOptions configures PostgreSQL authentication inspection.
type PostgresInspectorOptions struct {
	OnAuthFailure func()
}

// PostgresProxy inspects and relays PostgreSQL wire protocol handshakes.
type PostgresProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     PostgresInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewPostgresProxy creates a new PostgresProxy.
func NewPostgresProxy(client, upstream net.Conn, opts PostgresInspectorOptions) *PostgresProxy {
	return &PostgresProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the PostgreSQL protocol handshake and switches to raw proxy mode.
func (p *PostgresProxy) Run() (ProxyResult, bool, string) {
	// 1. Read frontend startup message (length 4 bytes + payload)
	for {
		var lenBuf [4]byte
		p.client.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(p.client, lenBuf[:]); err != nil {
			return p.result(), true, "failed reading client startup length: " + err.Error()
		}
		p.bytesIn.Add(4)

		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen < 8 || msgLen > 10000 {
			// Invalid or excessive startup length
			return p.result(), true, "invalid postgres startup packet length"
		}

		payload := make([]byte, msgLen-4)
		if _, err := io.ReadFull(p.client, payload); err != nil {
			return p.result(), true, "failed reading client startup payload: " + err.Error()
		}
		p.bytesIn.Add(int64(len(payload)))

		version := binary.BigEndian.Uint32(payload[:4])

		// Check for SSLRequest (80877103 = 0x04D2162F)
		if version == 80877103 {
			// Forward SSLRequest to upstream
			if _, err := p.upstream.Write(append(lenBuf[:], payload...)); err != nil {
				return p.result(), true, "failed writing SSLRequest to upstream: " + err.Error()
			}
			p.bytesOut.Add(int64(lenBufLen() + len(payload)))

			// Upstream replies with single byte: 'S' (SSL ok) or 'N' (no SSL)
			var resp [1]byte
			p.upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(p.upstream, resp[:]); err != nil {
				return p.result(), true, "failed reading SSL response from upstream: " + err.Error()
			}
			if _, err := p.client.Write(resp[:]); err != nil {
				return p.result(), false, ""
			}

			if resp[0] == 'S' {
				// TLS negotiation begins immediately between client and server.
				// Reset deadlines and switch to raw bidirectional streaming.
				p.client.SetDeadline(time.Time{})
				p.upstream.SetDeadline(time.Time{})
				proxyRes := Proxy(p.client, p.upstream)
				p.bytesIn.Add(proxyRes.BytesIn)
				p.bytesOut.Add(proxyRes.BytesOut)
				return p.result(), false, ""
			}
			// If 'N', loop back to read the subsequent standard StartupMessage in cleartext
			continue
		}

		// Forward standard StartupMessage to upstream
		if _, err := p.upstream.Write(append(lenBuf[:], payload...)); err != nil {
			return p.result(), true, "failed writing StartupMessage to upstream: " + err.Error()
		}
		p.bytesOut.Add(int64(lenBufLen() + len(payload)))
		break
	}

	// 2. Authentication handshake loop
	for {
		p.upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		var typeBuf [1]byte
		if _, err := io.ReadFull(p.upstream, typeBuf[:]); err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(1)
		msgType := typeBuf[0]

		var lenBuf [4]byte
		if _, err := io.ReadFull(p.upstream, lenBuf[:]); err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(4)
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen < 4 || msgLen > 65536 {
			return p.result(), true, "invalid backend message length"
		}

		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(p.upstream, body); err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(int64(len(body)))

		// Forward message to client
		packet := append(append(typeBuf[:], lenBuf[:]...), body...)
		if _, err := p.client.Write(packet); err != nil {
			return p.result(), false, ""
		}

		switch msgType {
		case 'E': // ErrorResponse
			fields := parsePostgresErrorFields(body)
			code := fields['C']
			if code == "28P01" || code == "28000" || strings.HasPrefix(code, "28") {
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
			return p.result(), false, ""

		case 'R': // Authentication request
			if len(body) >= 4 {
				authType := binary.BigEndian.Uint32(body[:4])
				if authType == 0 {
					// Auth OK! Wait for ReadyForQuery ('Z')
					continue
				}
				// Client will respond with password or SASL message
				p.client.SetReadDeadline(time.Now().Add(30 * time.Second))
				var clientType [1]byte
				if _, err := io.ReadFull(p.client, clientType[:]); err != nil {
					return p.result(), false, ""
				}
				p.bytesIn.Add(1)

				var clientLen [4]byte
				if _, err := io.ReadFull(p.client, clientLen[:]); err != nil {
					return p.result(), false, ""
				}
				p.bytesIn.Add(4)
				cMsgLen := binary.BigEndian.Uint32(clientLen[:])
				if cMsgLen < 4 || cMsgLen > 65536 {
					return p.result(), true, "invalid client auth message length"
				}

				cBody := make([]byte, cMsgLen-4)
				if _, err := io.ReadFull(p.client, cBody); err != nil {
					return p.result(), false, ""
				}
				p.bytesIn.Add(int64(len(cBody)))

				cPacket := append(append(clientType[:], clientLen[:]...), cBody...)
				if _, err := p.upstream.Write(cPacket); err != nil {
					return p.result(), false, ""
				}
			}

		case 'Z': // ReadyForQuery -> Handshake fully completed
			p.client.SetDeadline(time.Time{})
			p.upstream.SetDeadline(time.Time{})
			proxyRes := Proxy(p.client, p.upstream)
			p.bytesIn.Add(proxyRes.BytesIn)
			p.bytesOut.Add(proxyRes.BytesOut)
			return p.result(), false, ""
		}
	}
}

func (p *PostgresProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}

func lenBufLen() int {
	return 4
}

// parsePostgresErrorFields splits null-terminated field byte + string pairs from an ErrorResponse body.
func parsePostgresErrorFields(body []byte) map[byte]string {
	fields := make(map[byte]string)
	i := 0
	for i < len(body) {
		fieldType := body[i]
		if fieldType == 0 {
			break
		}
		i++
		nullIdx := bytes.IndexByte(body[i:], 0)
		if nullIdx == -1 {
			break
		}
		fields[fieldType] = string(body[i : i+nullIdx])
		i += nullIdx + 1
	}
	return fields
}
