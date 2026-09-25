package redis

import (
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

// Plugin implements sdk.Plugin for Redis protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "redis",
		Version:     "1.0.0",
		Description: "Redis RESP wire protocol inspector with command filtering and credential stuffing detection",
		Author:      "RouteWarden Team",
		Protocols:   []string{"redis"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["blocked_commands"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("blocked_commands must be a list of strings")
				}
			}
		default:
			return fmt.Errorf("blocked_commands must be a list of strings, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	var blocked []string
	if config != nil {
		if v, ok := config["blocked_commands"]; ok {
			switch items := v.(type) {
			case []string:
				blocked = items
			case []any:
				for _, item := range items {
					if s, ok := item.(string); ok {
						blocked = append(blocked, s)
					}
				}
			}
		}
	}
	return NewInspector(blocked), nil
}

// SelfTest executes synthetic in-memory test using net.Pipe.
// Tests that blocked commands (e.g. FLUSHALL) are actively intercepted and rejected.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := NewInspector([]string{"FLUSHALL"})

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-redis",
		ClientAddress: "127.0.0.1",
	}

	done := make(chan error, 1)
	var blocked bool
	var blockReason string

	go func() {
		_, b, r, err := insp.Run(ctx, clientB, upA)
		blocked = b
		blockReason = r
		done <- err
	}()

	// Synthetic client: sends FLUSHALL\r\n, then reads response
	clientDone := make(chan string, 1)

	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("FLUSHALL\r\n"))

		var buf [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientA.Read(buf[:])
		clientDone <- string(buf[:n])
	}()

	select {
	case <-done:
		resp := <-clientDone
		if !blocked {
			return errors.New("self-test failed: FLUSHALL command was not marked as blocked")
		}
		if !strings.Contains(resp, "-ERR command 'FLUSHALL' is blocked") {
			return fmt.Errorf("self-test failed: expected rejection banner, got %q (reason: %s)", resp, blockReason)
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}
