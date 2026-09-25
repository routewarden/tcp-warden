package tls_sni

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

// Plugin implements sdk.Plugin for TLS SNI domain inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "tls_sni",
		Version:     "1.0.0",
		Description: "Zero-decryption TLS ClientHello inspector extracting SNI domain names and enforcing domain allow/deny rules",
		Author:      "RouteWarden Team",
		Protocols:   []string{"tls", "sni"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	checkStringSlice := func(key string) error {
		if v, exists := config[key]; exists {
			switch items := v.(type) {
			case []string:
			case []any:
				for _, item := range items {
					if _, ok := item.(string); !ok {
						return fmt.Errorf("%s must be a list of strings", key)
					}
				}
			default:
				return fmt.Errorf("%s must be a list of strings, got %T", key, v)
			}
		}
		return nil
	}

	if err := checkStringSlice("allowed_domains"); err != nil {
		return err
	}
	return checkStringSlice("blocked_domains")
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config != nil {
		insp.AllowedDomains = extractStringSlice(config["allowed_domains"])
		insp.BlockedDomains = extractStringSlice(config["blocked_domains"])
	}
	return insp, nil
}

func extractStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []string:
		return v
	case []any:
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	}
	return nil
}

// SelfTest executes synthetic in-memory test using net.Pipe.
// Tests that TLS ClientHello with a blocked SNI is detected and blocked.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{
		BlockedDomains: []string{"*.malware.test"},
	}

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-tls-sni",
		ClientAddress: "127.0.0.1",
	}

	mockTLS := buildMockClientHello("phishing.malware.test")

	done := make(chan error, 1)
	var blocked bool
	var blockReason string

	go func() {
		_, b, r, err := insp.Run(ctx, clientB, upA)
		blocked = b
		blockReason = r
		done <- err
	}()

	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(mockTLS)
		clientA.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("self-test returned error: %w", err)
		}
		if !blocked {
			return errors.New("self-test failed: TLS SNI with blocked domain was not blocked")
		}
		if !strings.Contains(blockReason, "phishing.malware.test") {
			return fmt.Errorf("self-test failed: expected reason to contain domain, got %q", blockReason)
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

func buildMockClientHello(sni string) []byte {
	sniBytes := []byte(sni)

	extData := []byte{
		0, byte(len(sniBytes) + 3),
		0,
		0, byte(len(sniBytes)),
	}
	extData = append(extData, sniBytes...)

	ext := []byte{0, 0, 0, byte(len(extData))}
	ext = append(ext, extData...)

	extsBlock := []byte{0, byte(len(ext))}
	extsBlock = append(extsBlock, ext...)

	chBody := []byte{0x03, 0x03}
	chBody = append(chBody, make([]byte, 32)...)
	chBody = append(chBody, 0)
	chBody = append(chBody, 0, 2, 0x00, 0x9c)
	chBody = append(chBody, 1, 0)
	chBody = append(chBody, extsBlock...)

	chLen := len(chBody)
	hs := []byte{1, byte(chLen >> 16), byte(chLen >> 8), byte(chLen)}
	hs = append(hs, chBody...)

	recLen := len(hs)
	record := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	return append(record, hs...)
}
