package ftp_test

import (
	"testing"

	"github.com/routewarden/tcp-warden/plugins/ftp"
)

func TestFTPPlugin_SelfTest(t *testing.T) {
	p := &ftp.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("ftp SelfTest failed: %v", err)
	}
}

func TestFTPPlugin_ManifestAndConfig(t *testing.T) {
	p := &ftp.Plugin{}
	m := p.Manifest()
	if m.Name != "ftp" {
		t.Errorf("expected ftp, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(nil)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
