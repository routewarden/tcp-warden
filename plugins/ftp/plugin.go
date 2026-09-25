package ftp

import (
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

// Plugin implements sdk.Plugin for FTP protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "ftp",
		Version:     "1.0.0",
		Description: "FTP wire protocol inspector (RFC 959) detecting brute-force authentication failures and AUTH TLS handovers",
		Author:      "RouteWarden Team",
		Protocols:   []string{"ftp"},
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
// Tests that FTP authentication failure (530 Login incorrect) properly triggers OnAuthFailure.
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
		ServiceName:   "selftest-ftp",
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

	// Synthetic upstream server
	go func() {
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("220 ProFTPD Server ready.\r\n"))

		var buf [256]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:]) // USER

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("331 Password required for admin\r\n"))

		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:]) // PASS

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("530 Login incorrect.\r\n"))
	}()

	// Synthetic client
	go func() {
		var buf [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:]) // 220

		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("USER admin\r\n"))

		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:]) // 331

		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("PASS wrongpassword\r\n"))

		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:]) // 530
	}()

	select {
	case <-time.After(500 * time.Millisecond):
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: FTP 530 Login incorrect did not trigger OnAuthFailure")
		}
		return nil
	case err := <-done:
		if err != nil {
			return fmt.Errorf("self-test returned error: %w", err)
		}
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: FTP 530 Login incorrect did not trigger OnAuthFailure")
		}
		return nil
	}
}
