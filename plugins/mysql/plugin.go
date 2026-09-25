package mysql

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func init() {
	plugins.Register(&Plugin{})
}

// Plugin implements sdk.Plugin for MySQL protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "mysql",
		Version:     "1.0.0",
		Description: "MySQL and MariaDB wire protocol inspector detecting authentication failures and SSL handshakes",
		Author:      "RouteWarden Team",
		Protocols:   []string{"mysql", "mariadb"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["max_auth_failures"]; exists {
		switch v.(type) {
		case int, int64, float64:
		default:
			return fmt.Errorf("max_auth_failures must be an integer, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config != nil {
		if v, ok := config["max_auth_failures"]; ok {
			switch n := v.(type) {
			case int:
				insp.MaxAuthFailures = n
			case int64:
				insp.MaxAuthFailures = int(n)
			case float64:
				insp.MaxAuthFailures = int(n)
			}
		}
	}
	return insp, nil
}

// SelfTest executes synthetic in-memory test using net.Pipe.
// If MySQL authentication error code 1045 fails to trigger OnAuthFailure,
// the plugin is automatically disabled by returning an error.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	authFailureTriggered := false
	var mu sync.Mutex

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-mysql",
		ClientAddress: "127.0.0.1",
		AuthFailureFunc: func() {
			mu.Lock()
			authFailureTriggered = true
			mu.Unlock()
		},
	}

	insp := &Inspector{}
	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(ctx, clientB, upA)
		done <- err
	}()

	// Synthetic upstream server: sends handshake, reads client response, sends ERR 1045
	go func() {
		// Handshake packet: len=5, seq=0, payload=\n8.0.30\x00
		handshakePayload := []byte("\n8.0.30\x00")
		pkt := make([]byte, 4+len(handshakePayload))
		pkt[0] = byte(len(handshakePayload))
		pkt[3] = 0 // seq 0
		copy(pkt[4:], handshakePayload)
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(pkt)

		// Read client HandshakeResponse41
		var clientHeader [4]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(clientHeader[:])
		cLen := int(clientHeader[0]) | int(clientHeader[1])<<8 | int(clientHeader[2])<<16
		cPayload := make([]byte, cLen)
		_, _ = upB.Read(cPayload)

		// Send ERR packet: 0xFF, error code 1045 (0x15, 0x04), sqlstate "#28000", message
		errPayload := make([]byte, 1+2+6+len("Access denied"))
		errPayload[0] = 0xFF
		binary.LittleEndian.PutUint16(errPayload[1:3], 1045)
		copy(errPayload[3:9], "#28000")
		copy(errPayload[9:], "Access denied")

		errPkt := make([]byte, 4+len(errPayload))
		errPkt[0] = byte(len(errPayload) & 0xFF)
		errPkt[1] = byte((len(errPayload) >> 8) & 0xFF)
		errPkt[3] = 2 // seq 2
		copy(errPkt[4:], errPayload)

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(errPkt)
	}()

	// Synthetic client: reads handshake, sends response, reads ERR packet
	go func() {
		var hHeader [4]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(hHeader[:])
		hLen := int(hHeader[0]) | int(hHeader[1])<<8 | int(hHeader[2])<<16
		hPayload := make([]byte, hLen)
		_, _ = clientA.Read(hPayload)

		// Send simple client HandshakeResponse41 (caps = 0, no SSL)
		cResp := make([]byte, 32)
		pkt := make([]byte, 4+len(cResp))
		pkt[0] = byte(len(cResp))
		pkt[3] = 1 // seq 1
		copy(pkt[4:], cResp)
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(pkt)

		// Read forwarded ERR packet
		var errBuf [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(errBuf[:])
	}()

	select {
	case <-done:
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: mysql ERR packet 1045 did not trigger OnAuthFailure")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}
