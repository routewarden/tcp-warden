package mysql

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects MySQL/MariaDB wire protocol handshakes.
type Inspector struct {
	MaxAuthFailures int
}

// Run executes the MySQL protocol handshake and switches to raw proxy mode.
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

	// 1. Upstream sends Initial Handshake Packet (sequence 0)
	upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
	handshakePkt, err := readMySQLPacket(upstream)
	if err != nil {
		return result(err), true, "failed reading initial MySQL handshake: " + err.Error(), err
	}
	bytesOut.Add(int64(len(handshakePkt)))
	if _, err := client.Write(handshakePkt); err != nil {
		return result(err), false, "", err
	}

	// 2. Client sends HandshakeResponse41 (sequence 1)
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientPkt, err := readMySQLPacket(client)
	if err != nil {
		return result(err), true, "failed reading client handshake response: " + err.Error(), err
	}
	bytesIn.Add(int64(len(clientPkt)))

	// Check if CLIENT_SSL (0x00000800) is set in capabilities (first 4 bytes of packet payload)
	if len(clientPkt) >= 8 {
		caps := binary.LittleEndian.Uint32(clientPkt[4:8])
		if (caps & 0x00000800) != 0 {
			// SSL requested: forward SSL request to server and switch to TLS raw streaming
			if _, err := upstream.Write(clientPkt); err != nil {
				return result(err), true, "failed writing SSL request to upstream: " + err.Error(), err
			}
			client.SetDeadline(time.Time{})
			upstream.SetDeadline(time.Time{})
			proxyRes := protocol.Proxy(client, upstream)
			bytesIn.Add(proxyRes.BytesIn)
			bytesOut.Add(proxyRes.BytesOut)
			return result(nil), false, "", nil
		}
	}

	// Forward standard client response to upstream
	if _, err := upstream.Write(clientPkt); err != nil {
		return result(err), true, "failed forwarding client response to upstream: " + err.Error(), err
	}

	// 3. Upstream responds with OK (0x00), AuthSwitch (0xFE), or ERR (0xFF)
	for {
		upstream.SetReadDeadline(time.Now().Add(15 * time.Second))
		serverPkt, err := readMySQLPacket(upstream)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(serverPkt)))
		if _, err := client.Write(serverPkt); err != nil {
			return result(err), false, "", nil
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
					if ctx != nil {
						ctx.OnAuthFailure()
						ctx.OnSecurityEvent("auth_failure", "mysql_access_denied")
					}
				}
			}
			return result(nil), false, "", nil
		}

		if header == 0xFE {
			// AuthSwitchRequest: client will send AuthSwitchResponse
			client.SetReadDeadline(time.Now().Add(10 * time.Second))
			authSwitchResp, err := readMySQLPacket(client)
			if err != nil {
				return result(err), false, "", nil
			}
			bytesIn.Add(int64(len(authSwitchResp)))
			if _, err := upstream.Write(authSwitchResp); err != nil {
				return result(err), false, "", nil
			}
			continue
		}

		if header == 0x00 {
			// OK packet -> Authentication successful!
			client.SetDeadline(time.Time{})
			upstream.SetDeadline(time.Time{})
			proxyRes := protocol.Proxy(client, upstream)
			bytesIn.Add(proxyRes.BytesIn)
			bytesOut.Add(proxyRes.BytesOut)
			return result(nil), false, "", nil
		}
	}
}

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
