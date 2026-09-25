package echo_filter_test

import (
	"testing"

	"github.com/routewarden/tcp-warden/plugins/examples/echo_filter"
)

func TestEchoFilterPlugin_SelfTest(t *testing.T) {
	p := &echo_filter.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("echo_filter SelfTest failed: %v", err)
	}
}

func TestEchoFilterPlugin_ManifestAndConfig(t *testing.T) {
	p := &echo_filter.Plugin{}
	m := p.Manifest()
	if m.Name != "echo_filter" {
		t.Errorf("expected echo_filter, got %s", m.Name)
	}

	cfg := map[string]any{"banned_keywords": []string{"DROP", "DELETE"}}
	if err := p.ValidateConfig(cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(cfg)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
