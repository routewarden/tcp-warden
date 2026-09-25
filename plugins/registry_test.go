package plugins_test

import (
	"errors"
	"net"
	"testing"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

type dummyHealthyPlugin struct{}

func (d *dummyHealthyPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "healthy-plugin",
		Version:     "1.0.0",
		Description: "A test healthy plugin",
		Protocols:   []string{"healthy-proto"},
	}
}

func (d *dummyHealthyPlugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (d *dummyHealthyPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return nil, nil
}

func (d *dummyHealthyPlugin) SelfTest() error {
	return nil
}

type dummyFaultyPlugin struct{}

func (d *dummyFaultyPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "faulty-plugin",
		Version:     "1.0.0",
		Description: "A plugin that deliberately fails its self-test",
		Protocols:   []string{"faulty-proto"},
	}
}

func (d *dummyFaultyPlugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (d *dummyFaultyPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return nil, nil
}

func (d *dummyFaultyPlugin) SelfTest() error {
	return errors.New("synthetic self-test failure: handshake assertion failed")
}

func TestPluginRegistry_SelfTestingAndAutoDisable(t *testing.T) {
	reg := plugins.NewRegistry()

	healthy := &dummyHealthyPlugin{}
	faulty := &dummyFaultyPlugin{}

	reg.Register(healthy)
	reg.Register(faulty)

	// Before running self-tests, status should be PENDING
	st, _ := reg.GetStatus("healthy-plugin")
	if st != plugins.StatusPending {
		t.Fatalf("expected PENDING, got %v", st)
	}

	results := reg.RunSelfTests()

	// Verify healthy plugin
	hRes, ok := results["healthy-plugin"]
	if !ok || !hRes.Passed {
		t.Fatalf("expected healthy plugin to pass self-test, got %+v", hRes)
	}
	if !reg.IsActive("healthy-plugin") {
		t.Errorf("healthy-plugin should be active")
	}
	if !reg.IsActive("healthy-proto") {
		t.Errorf("healthy-proto should be active")
	}

	// Verify faulty plugin is auto-disabled
	fRes, ok := results["faulty-plugin"]
	if !ok || fRes.Passed {
		t.Fatalf("expected faulty plugin to fail self-test, got %+v", fRes)
	}
	if reg.IsActive("faulty-plugin") {
		t.Errorf("faulty-plugin should NOT be active")
	}
	if reg.IsActive("faulty-proto") {
		t.Errorf("faulty-proto should NOT be active")
	}

	status, err := reg.GetStatus("faulty-proto")
	if status != plugins.StatusDisabled {
		t.Errorf("expected StatusDisabled, got %v", status)
	}
	if err == nil || err.Error() != "synthetic self-test failure: handshake assertion failed" {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify List
	list := reg.List()
	if len(list) != 2 {
		t.Errorf("expected 2 plugins in list, got %d", len(list))
	}
}

func TestSDK_DefaultContext(t *testing.T) {
	authFailed := false
	secAction := ""
	secReason := ""

	ctx := &sdk.DefaultContext{
		ServiceName:   "test-svc",
		ClientAddress: "192.0.2.1",
		AuthFailureFunc: func() {
			authFailed = true
		},
		SecurityFunc: func(action, reason string) {
			secAction = action
			secReason = reason
		},
	}

	if ctx.Service() != "test-svc" {
		t.Errorf("expected test-svc, got %s", ctx.Service())
	}
	if ctx.ClientIP() != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1, got %s", ctx.ClientIP())
	}

	ctx.OnAuthFailure()
	if !authFailed {
		t.Errorf("expected authFailed to be true")
	}

	ctx.OnSecurityEvent("blocked", "bad_packet")
	if secAction != "blocked" || secReason != "bad_packet" {
		t.Errorf("expected security event recorded")
	}

	p1, p2 := net.Pipe()
	p1.Close()
	p2.Close()
}
