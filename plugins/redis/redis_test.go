package redis_test

import (
	"testing"

	"github.com/routewarden/tcp-warden/plugins/redis"
)

func TestRedisPlugin_SelfTest(t *testing.T) {
	p := &redis.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("redis SelfTest failed: %v", err)
	}
}

func TestRedisPlugin_ManifestAndConfig(t *testing.T) {
	p := &redis.Plugin{}
	m := p.Manifest()
	if m.Name != "redis" {
		t.Errorf("expected redis, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"blocked_commands": []string{"FLUSHALL", "CONFIG"}}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(map[string]any{"blocked_commands": []any{"FLUSHALL"}})
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
