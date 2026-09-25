package postgres_test

import (
	"testing"

	"github.com/routewarden/tcp-warden/plugins/postgres"
)

func TestPostgresPlugin_SelfTest(t *testing.T) {
	p := &postgres.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("postgres SelfTest failed: %v", err)
	}
}

func TestPostgresPlugin_ManifestAndConfig(t *testing.T) {
	p := &postgres.Plugin{}
	m := p.Manifest()
	if m.Name != "postgres" {
		t.Errorf("expected postgres, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 3}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "invalid"}); err == nil {
		t.Errorf("invalid config accepted")
	}

	insp, err := p.CreateInspector(map[string]any{"max_auth_failures": 5})
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
