package mqtt_test

import (
	"testing"

	"github.com/routewarden/tcp-warden/plugins/examples/mqtt"
)

func TestMQTTPlugin_SelfTest(t *testing.T) {
	p := &mqtt.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("mqtt SelfTest failed: %v", err)
	}
}

func TestMQTTPlugin_ManifestAndConfig(t *testing.T) {
	p := &mqtt.Plugin{}
	m := p.Manifest()
	if m.Name != "mqtt" {
		t.Errorf("expected mqtt, got %s", m.Name)
	}

	cfg := map[string]any{
		"blocked_client_id_prefixes": []string{"bot-"},
		"max_client_id_len":          64,
	}
	if err := p.ValidateConfig(cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(cfg)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
