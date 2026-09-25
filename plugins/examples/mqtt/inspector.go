package mqtt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects MQTT CONNECT packets for unauthorized ClientIDs and protocol anomalies.
type Inspector struct {
	BlockedClientIDPrefixes []string
	MaxClientIDLen          int
}

// Run inspects initial MQTT CONNECT packet and switches to proxy mode if valid.
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

	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 1. Read MQTT Fixed Header: Packet Type (1 byte)
	var typeBuf [1]byte
	if _, err := io.ReadFull(client, typeBuf[:]); err != nil {
		return result(err), true, "failed reading MQTT packet type: " + err.Error(), err
	}
	bytesIn.Add(1)

	packetType := typeBuf[0] >> 4
	if packetType != 1 { // 1 = CONNECT
		return result(nil), true, fmt.Sprintf("expected MQTT CONNECT packet (1), got %d", packetType), nil
	}

	// 2. Read Remaining Length (variable byte integer: 1 to 4 bytes)
	remLen, remLenBytes, err := readVarInt(client)
	if err != nil {
		return result(err), true, "invalid MQTT remaining length: " + err.Error(), err
	}
	bytesIn.Add(int64(len(remLenBytes)))

	if remLen < 10 || remLen > 65536 {
		return result(nil), true, "invalid MQTT CONNECT packet length", nil
	}

	payload := make([]byte, remLen)
	if _, err := io.ReadFull(client, payload); err != nil {
		return result(err), true, "failed reading MQTT CONNECT payload: " + err.Error(), err
	}
	bytesIn.Add(int64(len(payload)))

	// 3. Inspect Variable Header (Protocol Name & Level)
	clientID, parseErr := parseMQTTConnectPayload(payload)
	if parseErr != nil {
		return result(nil), true, "malformed MQTT CONNECT packet: " + parseErr.Error(), nil
	}

	// 4. Validate ClientID
	if insp.MaxClientIDLen > 0 && len(clientID) > insp.MaxClientIDLen {
		return result(nil), true, fmt.Sprintf("MQTT ClientID exceeds max allowed length (%d > %d)", len(clientID), insp.MaxClientIDLen), nil
	}

	for _, prefix := range insp.BlockedClientIDPrefixes {
		if prefix != "" && strings.HasPrefix(strings.ToLower(clientID), strings.ToLower(prefix)) {
			// Reply with CONNACK: Not authorized (Return code 5 in MQTT 3.1.1)
			connack := []byte{0x20, 0x02, 0x00, 0x05}
			client.Write(connack)
			bytesOut.Add(int64(len(connack)))
			if ctx != nil {
				ctx.OnSecurityEvent("blocked", "blocked_mqtt_client_id_"+clientID)
			}
			return result(nil), true, fmt.Sprintf("blocked MQTT ClientID %q matching prefix %q", clientID, prefix), nil
		}
	}

	// 5. Forward full CONNECT packet to upstream
	upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fullPacket := append(typeBuf[:], remLenBytes...)
	fullPacket = append(fullPacket, payload...)
	if _, err := upstream.Write(fullPacket); err != nil {
		return result(err), false, "", err
	}
	bytesOut.Add(int64(len(fullPacket)))

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	bufferedClient := &protocol.BufferedConn{
		Reader: bytes.NewReader(nil),
		Conn:   client,
	}

	proxyRes := protocol.Proxy(bufferedClient, upstream)
	bytesIn.Add(proxyRes.BytesIn)
	bytesOut.Add(proxyRes.BytesOut)

	return result(proxyRes.Err), false, "", nil
}

func readVarInt(r io.Reader) (int, []byte, error) {
	var multiplier = 1
	var value = 0
	var raw []byte
	var buf [1]byte

	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, nil, err
		}
		raw = append(raw, buf[0])
		digit := int(buf[0])
		value += (digit & 127) * multiplier
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, nil, fmt.Errorf("MQTT varint exceeds 4 bytes")
		}
		if (digit & 128) == 0 {
			break
		}
	}
	return value, raw, nil
}

func parseMQTTConnectPayload(payload []byte) (string, error) {
	if len(payload) < 10 {
		return "", fmt.Errorf("payload too short")
	}

	protoNameLen := int(binary.BigEndian.Uint16(payload[0:2]))
	if len(payload) < 2+protoNameLen+4 {
		return "", fmt.Errorf("truncated protocol name")
	}

	pos := 2 + protoNameLen
	// Skip proto level (1 byte) + flags (1 byte) + keepalive (2 bytes)
	pos += 4

	if pos+2 > len(payload) {
		return "", fmt.Errorf("truncated client ID length")
	}
	clientIDLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	if pos+clientIDLen > len(payload) {
		return "", fmt.Errorf("truncated client ID string")
	}

	return string(payload[pos : pos+clientIDLen]), nil
}
