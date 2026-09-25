package postgres

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects PostgreSQL wire protocol handshakes.
type Inspector struct {
	MaxAuthFailures int
}

// Run executes the PostgreSQL protocol handshake and switches to raw proxy mode.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn atomic.Int64
	var bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{
			BytesIn:  bytesIn.Load(),
			BytesOut: bytesOut.Load(),
			Err:      err,
		}
	}

	// 1. Read frontend startup message (length 4 bytes + payload)
	for {
		var lenBuf [4]byte
		client.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
			return result(err), true, "failed reading client startup length: " + err.Error(), err
		}
		bytesIn.Add(4)

		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen < 8 || msgLen > 10000 {
			return result(nil), true, "invalid postgres startup packet length", nil
		}

		payload := make([]byte, msgLen-4)
		if _, err := io.ReadFull(client, payload); err != nil {
			return result(err), true, "failed reading client startup payload: " + err.Error(), err
		}
		bytesIn.Add(int64(len(payload)))

		version := binary.BigEndian.Uint32(payload[:4])

		// Check for SSLRequest (80877103 = 0x04D2162F)
		if version == 80877103 {
			// Forward SSLRequest to upstream
			if _, err := upstream.Write(append(lenBuf[:], payload...)); err != nil {
				return result(err), true, "failed writing SSLRequest to upstream: " + err.Error(), err
			}
			bytesOut.Add(int64(4 + len(payload)))

			// Upstream replies with single byte: 'S' (SSL ok) or 'N' (no SSL)
			var resp [1]byte
			upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(upstream, resp[:]); err != nil {
				return result(err), true, "failed reading SSL response from upstream: " + err.Error(), err
			}
			if _, err := client.Write(resp[:]); err != nil {
				return result(err), false, "", err
			}

			if resp[0] == 'S' {
				// TLS negotiation begins immediately between client and server.
				client.SetDeadline(time.Time{})
				upstream.SetDeadline(time.Time{})
				proxyRes := protocol.Proxy(client, upstream)
				bytesIn.Add(proxyRes.BytesIn)
				bytesOut.Add(proxyRes.BytesOut)
				return result(nil), false, "", nil
			}
			// If 'N', loop back to read the subsequent standard StartupMessage in cleartext
			continue
		}

		// Forward standard StartupMessage to upstream
		if _, err := upstream.Write(append(lenBuf[:], payload...)); err != nil {
			return result(err), true, "failed writing StartupMessage to upstream: " + err.Error(), err
		}
		bytesOut.Add(int64(4 + len(payload)))
		break
	}

	// 2. Authentication handshake loop
	for {
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		var typeBuf [1]byte
		if _, err := io.ReadFull(upstream, typeBuf[:]); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(1)
		msgType := typeBuf[0]

		var lenBuf [4]byte
		if _, err := io.ReadFull(upstream, lenBuf[:]); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(4)
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen < 4 || msgLen > 65536 {
			return result(nil), true, "invalid backend message length", nil
		}

		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(upstream, body); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(body)))

		// Forward message to client
		packet := append(append(typeBuf[:], lenBuf[:]...), body...)
		if _, err := client.Write(packet); err != nil {
			return result(err), false, "", nil
		}

		switch msgType {
		case 'E': // ErrorResponse
			fields := parsePostgresErrorFields(body)
			code := fields['C']
			if code == "28P01" || code == "28000" || strings.HasPrefix(code, "28") {
				if ctx != nil {
					ctx.OnAuthFailure()
					ctx.OnSecurityEvent("auth_failure", "postgres_auth_error_"+code)
				}
			}
			return result(nil), false, "", nil

		case 'R': // Authentication request
			if len(body) >= 4 {
				authType := binary.BigEndian.Uint32(body[:4])
				if authType == 0 {
					// Auth OK! Wait for ReadyForQuery ('Z')
					continue
				}
				// Client responds with password/SASL response
				client.SetReadDeadline(time.Now().Add(30 * time.Second))
				var clientType [1]byte
				if _, err := io.ReadFull(client, clientType[:]); err != nil {
					return result(err), false, "", nil
				}
				bytesIn.Add(1)

				var clientLen [4]byte
				if _, err := io.ReadFull(client, clientLen[:]); err != nil {
					return result(err), false, "", nil
				}
				bytesIn.Add(4)
				cMsgLen := binary.BigEndian.Uint32(clientLen[:])
				if cMsgLen < 4 || cMsgLen > 65536 {
					return result(nil), true, "invalid client auth message length", nil
				}

				cBody := make([]byte, cMsgLen-4)
				if _, err := io.ReadFull(client, cBody); err != nil {
					return result(err), false, "", nil
				}
				bytesIn.Add(int64(len(cBody)))

				cPacket := append(append(clientType[:], clientLen[:]...), cBody...)
				if _, err := upstream.Write(cPacket); err != nil {
					return result(err), false, "", nil
				}
			}

		case 'Z': // ReadyForQuery -> Handshake fully completed
			client.SetDeadline(time.Time{})
			upstream.SetDeadline(time.Time{})
			proxyRes := protocol.Proxy(client, upstream)
			bytesIn.Add(proxyRes.BytesIn)
			bytesOut.Add(proxyRes.BytesOut)
			return result(nil), false, "", nil
		}
	}
}

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
