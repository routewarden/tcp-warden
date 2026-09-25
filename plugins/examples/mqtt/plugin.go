package mqtt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func init() {
	plugins.Register(&Plugin{})
}

// Plugin implements sdk.Plugin for IoT MQTT protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "mqtt",
		Version:     "1.0.0",
		Description: "Example custom RouteWarden plugin for IoT MQTT brokers with ClientID filtering and protocol anomaly detection",
		Author:      "Community Contributor",
		Protocols:   []string{"mqtt"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["blocked_client_id_prefixes"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("blocked_client_id_prefixes must contain strings")
				}
			}
		default:
			return fmt.Errorf("blocked_client_id_prefixes must be a list of strings, got %T", v)
		}
	}
	if v, exists := config["max_client_id_len"]; exists {
		switch v.(type) {
		case int, int64, float64:
		default:
			return fmt.Errorf("max_client_id_len must be an integer, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{
		MaxClientIDLen: 128,
	}
	if config != nil {
		if v, ok := config["blocked_client_id_prefixes"]; ok {
			switch items := v.(type) {
			case []string:
				insp.BlockedClientIDPrefixes = items
			case []any:
				for _, item := range items {
					if s, ok := item.(string); ok {
						insp.BlockedClientIDPrefixes = append(insp.BlockedClientIDPrefixes, s)
					}
				}
			}
		}
		if v, ok := config["max_client_id_len"]; ok {
			switch n := v.(type) {
			case int:
				insp.MaxClientIDLen = n
			case int64:
				insp.MaxClientIDLen = int(n)
			case float64:
				insp.MaxClientIDLen = int(n)
			}
		}
	}
	return insp, nil
}

// SelfTest executes synthetic in-memory test using net.Pipe.
// Tests that MQTT CONNECT packet with a blocked ClientID prefix is rejected with CONNACK (code 5).
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{
		BlockedClientIDPrefixes: []string{"bot-"},
	}

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-mqtt",
		ClientAddress: "127.0.0.1",
	}

	connectPkt := buildMockMQTTConnectPacket("bot-crawler-99")

	done := make(chan error, 1)
	var blocked bool
	var blockReason string

	go func() {
		_, b, r, err := insp.Run(ctx, clientB, upA)
		blocked = b
		blockReason = r
		done <- err
	}()

	clientDone := make(chan []byte, 1)

	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(connectPkt)

		var buf [16]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientA.Read(buf[:])
		clientDone <- buf[:n]
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("self-test returned error: %w", err)
		}
		if !blocked {
			return errors.New("self-test failed: unauthorized MQTT ClientID was not blocked")
		}
		if !strings.Contains(blockReason, "bot-crawler-99") {
			return fmt.Errorf("self-test failed: expected reason to contain client ID, got %q", blockReason)
		}
		resp := <-clientDone
		// CONNACK is 0x20 0x02 0x00 0x05 (Not authorized)
		if len(resp) < 4 || resp[0] != 0x20 || resp[3] != 0x05 {
			return fmt.Errorf("self-test failed: expected CONNACK not authorized (0x05), got %x", resp)
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

func buildMockMQTTConnectPacket(clientID string) []byte {
	// Protocol Name: "MQTT" (len 4)
	var varHeader []byte
	varHeader = append(varHeader, 0x00, 0x04, 'M', 'Q', 'T', 'T')
	varHeader = append(varHeader, 0x04)       // Protocol Level 4 (3.1.1)
	varHeader = append(varHeader, 0x02)       // Flags: CleanSession
	varHeader = append(varHeader, 0x00, 0x3C) // Keepalive 60s

	// Payload: ClientID
	var payload []byte
	cidBytes := []byte(clientID)
	var cidLen [2]byte
	binary.BigEndian.PutUint16(cidLen[:], uint16(len(cidBytes)))
	payload = append(payload, cidLen[:]...)
	payload = append(payload, cidBytes...)

	body := append(varHeader, payload...)
	remLen := len(body)

	// Fixed header: 0x10 (CONNECT) + remLen (assuming < 128 for test)
	pkt := []byte{0x10, byte(remLen)}
	return append(pkt, body...)
}
