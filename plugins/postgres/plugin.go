package postgres

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

// Plugin implements sdk.Plugin for PostgreSQL protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "postgres",
		Version:     "1.0.0",
		Description: "PostgreSQL wire protocol inspector with credential stuffing detection and SSL handling",
		Author:      "RouteWarden Team",
		Protocols:   []string{"postgres", "postgresql"},
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

// SelfTest runs an in-memory synthetic self-test using net.Pipe().
// If the inspector fails to detect auth errors or deadlocks, an error is returned,
// which causes the daemon to automatically disable the plugin.
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
		ServiceName:   "selftest-postgres",
		ClientAddress: "127.0.0.1",
		AuthFailureFunc: func() {
			mu.Lock()
			authFailureTriggered = true
			mu.Unlock()
		},
	}

	insp := &Inspector{}
	done := make(chan error, 1)

	// Run inspector in background goroutine
	go func() {
		_, _, _, err := insp.Run(ctx, clientB, upA)
		done <- err
	}()

	// Synthetic client: sends StartupMessage, then reads response
	go func() {
		var startup [8]byte
		binary.BigEndian.PutUint32(startup[0:4], 8)
		binary.BigEndian.PutUint32(startup[4:8], 196608) // Protocol 3.0
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(startup[:])

		var respBuf [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(respBuf[:])
	}()

	// Synthetic server: reads StartupMessage, sends ErrorResponse with code 28P01
	go func() {
		var buf [8]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:])

		// Build ErrorResponse ('E') with code 28P01 (password auth failed)
		errBody := []byte("SFATAL\x00C28P01\x00Mpassword authentication failed for user test\x00\x00")
		var header [5]byte
		header[0] = 'E'
		binary.BigEndian.PutUint32(header[1:5], uint32(len(errBody)+4))

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(append(header[:], errBody...))
	}()

	select {
	case <-done:
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: postgres ErrorResponse 28P01 did not trigger OnAuthFailure")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}
