package mysql_test

import (
	"testing"

	"github.com/routewarden/tcp-warden/plugins/mysql"
)

func TestMySQLPlugin_SelfTest(t *testing.T) {
	p := &mysql.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("mysql SelfTest failed: %v", err)
	}
}

func TestMySQLPlugin_ManifestAndConfig(t *testing.T) {
	p := &mysql.Plugin{}
	m := p.Manifest()
	if m.Name != "mysql" {
		t.Errorf("expected mysql, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(nil)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
