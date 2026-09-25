package echo_filter

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func init() {
	plugins.Register(&Plugin{})
}

// Plugin demonstrates an example third-party RouteWarden custom plugin.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "echo_filter",
		Version:     "1.0.0",
		Description: "Example custom RouteWarden plugin that scans client payloads for banned signature strings or exploit keywords",
		Author:      "Community Contributor",
		Protocols:   []string{"echo_filter", "text_filter"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["banned_keywords"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("banned_keywords must contain strings")
				}
			}
		default:
			return fmt.Errorf("banned_keywords must be a list of strings, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	var kws []string
	if config != nil {
		if v, ok := config["banned_keywords"]; ok {
			switch items := v.(type) {
			case []string:
				kws = items
			case []any:
				for _, item := range items {
					if s, ok := item.(string); ok {
						kws = append(kws, s)
					}
				}
			}
		}
	}
	return &Inspector{BannedKeywords: kws}, nil
}

// SelfTest executes synthetic in-memory test using net.Pipe.
// Verifies that traffic containing banned keywords is rejected.
// If this self-test fails, RouteWarden will automatically disable the plugin.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{
		BannedKeywords: []string{"EXPLOIT", "DROP TABLE"},
	}

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-echo-filter",
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

	var clientResp string
	var mu sync.Mutex

	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("GET /search?q=EXPLOIT_PAYLOAD HTTP/1.1\r\n\r\n"))

		var buf [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientA.Read(buf[:])
		mu.Lock()
		clientResp = string(buf[:n])
		mu.Unlock()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("self-test returned error: %w", err)
		}
		if !blocked {
			return errors.New("self-test failed: banned keyword was not blocked")
		}
		mu.Lock()
		resp := clientResp
		mu.Unlock()
		if !strings.Contains(resp, "ROUTEWARDEN_BLOCKED") {
			return fmt.Errorf("self-test failed: expected rejection banner, got %q (reason: %s)", resp, blockReason)
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}
