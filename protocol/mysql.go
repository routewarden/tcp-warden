package protocol

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// MySQLInspectorOptions configures MySQL authentication inspection.
type MySQLInspectorOptions struct {
	OnAuthFailure func()
}

// MySQLProxy inspects and relays MySQL wire protocol handshakes.
type MySQLProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     MySQLInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewMySQLProxy creates a new MySQLProxy.
func NewMySQLProxy(client, upstream net.Conn, opts MySQLInspectorOptions) *MySQLProxy {
	return &MySQLProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the MySQL protocol handshake and switches to raw proxy mode.
func (p *MySQLProxy) Run() (ProxyResult, bool, string) {
	// 1. Upstream sends Initial Handshake Packet (sequence 0)
	p.upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
	handshakePkt, err := readMySQLPacket(p.upstream)
	if err != nil {
		return p.result(), true, "failed reading initial MySQL handshake: " + err.Error()
	}
	p.bytesOut.Add(int64(len(handshakePkt)))
	if _, err := p.client.Write(handshakePkt); err != nil {
		return p.result(), false, ""
	}

	// 2. Client sends HandshakeResponse41 (sequence 1)
	p.client.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientPkt, err := readMySQLPacket(p.client)
	if err != nil {
		return p.result(), true, "failed reading client handshake response: " + err.Error()
	}
	p.bytesIn.Add(int64(len(clientPkt)))

	// Check if CLIENT_SSL (0x00000800) is set in capabilities (first 4 bytes of packet payload)
	if len(clientPkt) >= 8 {
		caps := binary.LittleEndian.Uint32(clientPkt[4:8])
		if (caps & 0x00000800) != 0 {
			// SSL requested: forward SSL request to server and switch to TLS raw streaming
			if _, err := p.upstream.Write(clientPkt); err != nil {
				return p.result(), true, "failed writing SSL request to upstream: " + err.Error()
			}
			p.client.SetDeadline(time.Time{})
			p.upstream.SetDeadline(time.Time{})
			proxyRes := Proxy(p.client, p.upstream)
			p.bytesIn.Add(proxyRes.BytesIn)
			p.bytesOut.Add(proxyRes.BytesOut)
			return p.result(), false, ""
		}
	}

	// Forward standard client response to upstream
	if _, err := p.upstream.Write(clientPkt); err != nil {
		return p.result(), true, "failed forwarding client response to upstream: " + err.Error()
	}

	// 3. Upstream responds with OK (0x00), AuthSwitch (0xFE), or ERR (0xFF)
	for {
		p.upstream.SetReadDeadline(time.Now().Add(15 * time.Second))
		serverPkt, err := readMySQLPacket(p.upstream)
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(int64(len(serverPkt)))
		if _, err := p.client.Write(serverPkt); err != nil {
			return p.result(), false, ""
		}

		if len(serverPkt) < 5 {
			continue
		}

		payload := serverPkt[4:]
		header := payload[0]

		if header == 0xFF {
			// ERR packet
			if len(payload) >= 3 {
				errorCode := binary.LittleEndian.Uint16(payload[1:3])
				// 1045: ER_ACCESS_DENIED_ERROR, 1044: ER_DBACCESS_DENIED_ERROR
				if errorCode == 1045 || errorCode == 1044 {
					if p.opts.OnAuthFailure != nil {
						p.opts.OnAuthFailure()
					}
				}
			}
			return p.result(), false, ""
		}

		if header == 0xFE {
			// AuthSwitchRequest: client will send AuthSwitchResponse
			p.client.SetReadDeadline(time.Now().Add(10 * time.Second))
			authSwitchResp, err := readMySQLPacket(p.client)
			if err != nil {
				return p.result(), false, ""
			}
			p.bytesIn.Add(int64(len(authSwitchResp)))
			if _, err := p.upstream.Write(authSwitchResp); err != nil {
				return p.result(), false, ""
			}
			continue
		}

		if header == 0x00 {
			// OK packet -> Authentication successful!
			p.client.SetDeadline(time.Time{})
			p.upstream.SetDeadline(time.Time{})
			proxyRes := Proxy(p.client, p.upstream)
			p.bytesIn.Add(proxyRes.BytesIn)
			p.bytesOut.Add(proxyRes.BytesOut)
			return p.result(), false, ""
		}
	}
}

func (p *MySQLProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}

// readMySQLPacket reads a complete 4-byte header + payload packet.
func readMySQLPacket(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	packet := make([]byte, 4+payloadLen)
	copy(packet[:4], header[:])
	if _, err := io.ReadFull(r, packet[4:]); err != nil {
		return nil, err
	}
	return packet, nil
}
