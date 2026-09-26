package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

type mockValidationPlugin struct{}

func (m *mockValidationPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:      "postgres",
		Version:   "1.0.0",
		Protocols: []string{"postgres"},
	}
}

func (m *mockValidationPlugin) ValidateConfig(map[string]any) error { return nil }
func (m *mockValidationPlugin) CreateInspector(map[string]any) (sdk.Inspector, error) {
	return nil, nil
}
func (m *mockValidationPlugin) SelfTest() error { return nil }

func init() {
	plugins.Register(&mockValidationPlugin{})
}

func TestParseYAML(t *testing.T) {
	os.Setenv("TEST_LAPI_KEY", "secret-key-123")
	defer os.Unsetenv("TEST_LAPI_KEY")

	yamlData := `
version: "1.0"

global:
  max_connections: 5000
  ban_duration: "2h"
  ban_after_failures: 5
  log_file: "/tmp/tcp-warden.jsonl"
  ip_filter:
    allow:
      - "127.0.0.1"
      - "10.0.0.0/8"

api:
  enabled: true
  listen: ":9091"

crowdsec:
  enabled: true
  lapi_url: "http://127.0.0.1:8080"
  api_key: "${TEST_LAPI_KEY}"
  update_frequency: "15s"

services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
    rate_limit:
      connections_per_minute: 20
      burst: 5
    ip_filter:
      deny:
        - "198.51.100.0/24"
    geo_block:
      deny_countries:
        - "CN"
        - "RU"
    ssh:
      banner: "RouteWarden SSH"
      max_auth_tries: 3

  smtp:
    listen: ":2525"
    upstream: "127.0.0.1:25"
    protocol: "smtp"
    response:
      mode: "reject"
      reject_message: "554 Rejected"
`

	cfg, err := Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("Failed to parse valid YAML: %v", err)
	}

	if cfg.Global.MaxConnections != 5000 {
		t.Errorf("Expected MaxConnections 5000, got %d", cfg.Global.MaxConnections)
	}
	if cfg.Global.BanDuration.Duration() != 2*time.Hour {
		t.Errorf("Expected BanDuration 2h, got %v", cfg.Global.BanDuration.Duration())
	}
	if cfg.CrowdSec.APIKey != "secret-key-123" {
		t.Errorf("Expected CrowdSec APIKey 'secret-key-123', got %q", cfg.CrowdSec.APIKey)
	}
	if cfg.CrowdSec.UpdateFrequency.Duration() != 15*time.Second {
		t.Errorf("Expected UpdateFrequency 15s, got %v", cfg.CrowdSec.UpdateFrequency.Duration())
	}

	sshSvc, ok := cfg.Services["ssh"]
	if !ok {
		t.Fatalf("Expected 'ssh' service in map")
	}
	if sshSvc.Protocol != "ssh" {
		t.Errorf("Expected protocol 'ssh', got %q", sshSvc.Protocol)
	}
	if sshSvc.RateLimit.ConnectionsPerMinute != 20 {
		t.Errorf("Expected 20 conns/min, got %d", sshSvc.RateLimit.ConnectionsPerMinute)
	}
	if len(sshSvc.GeoBlock.DenyCountries) != 2 {
		t.Errorf("Expected 2 denied countries, got %d", len(sshSvc.GeoBlock.DenyCountries))
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty services",
			yaml:    `version: "1.0"`,
			wantErr: "no services defined",
		},
		{
			name: "duplicate listen address",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
  svc2:
    listen: ":2222"
    upstream: "127.0.0.1:23"
`,
			wantErr: "duplicate listen address",
		},
		{
			name: "invalid CIDR",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    ip_filter:
      allow: ["not-an-ip"]
`,
			wantErr: "invalid allowed IP/CIDR",
		},
		{
			name: "unsupported protocol",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "unknown_proto"
`,
			wantErr: "requires plugin",
		},
		{
			name: "disabled by default plugin error",
			yaml: `
services:
  svc1:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
`,
			wantErr: "requires plugin \"postgres\" which is DISABLED by default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if err != nil && !testingContains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestPluginEnablementValidation(t *testing.T) {
	yamlData := `
version: "1.0"
plugins:
  postgres:
    enabled: true
  mongodb:
    enabled: true
    source: "https://github.com/routewarden/plugin-mongodb"
services:
  db:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
`
	cfg, err := Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("expected enabled plugin configuration to pass validation, got: %v", err)
	}
	if !cfg.IsPluginEnabled("postgres") {
		t.Errorf("expected postgres to be enabled")
	}
	if cfg.Plugins.Entries["mongodb"].Source != "https://github.com/routewarden/plugin-mongodb" {
		t.Errorf("expected mongodb source to be parsed, got %s", cfg.Plugins.Entries["mongodb"].Source)
	}
}

func TestUpdatePluginEnablement(t *testing.T) {
	initialYAML := `# Header comment
version: "1.0"

# Plugin section comment
plugins:
  postgres:
    enabled: false # inline comment
  mysql:
    enabled: false

services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
`
	tmpFile, err := os.CreateTemp("", "tcp-warden-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(initialYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// 1. Enable postgres
	if err := UpdatePluginEnablement(tmpFile.Name(), "postgres", true); err != nil {
		t.Fatalf("failed to update postgres to true: %v", err)
	}

	cfg1, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	if !cfg1.IsPluginEnabled("postgres") {
		t.Errorf("expected postgres to be enabled after UpdatePluginEnablement")
	}

	// 2. Add a new plugin: redis -> true
	if err := UpdatePluginEnablement(tmpFile.Name(), "redis", true); err != nil {
		t.Fatalf("failed to update redis to true: %v", err)
	}

	cfg2, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	if !cfg2.IsPluginEnabled("redis") {
		t.Errorf("expected redis to be enabled after UpdatePluginEnablement")
	}

	// 3. Disable postgres again
	if err := UpdatePluginEnablement(tmpFile.Name(), "postgres", false); err != nil {
		t.Fatalf("failed to disable postgres: %v", err)
	}

	cfg3, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	if cfg3.IsPluginEnabled("postgres") {
		t.Errorf("expected postgres to be disabled after UpdatePluginEnablement(false)")
	}

	// 4. Verify comments were preserved
	content, _ := os.ReadFile(tmpFile.Name())
	if !strings.Contains(string(content), "# Header comment") {
		t.Errorf("expected comments to be preserved in YAML")
	}
}

func testingContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && (s[:len(substr)] == substr || testingContains(s[1:], substr))))
}

