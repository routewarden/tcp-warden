package sdk

import (
	"context"
	"net"
	"time"
)

// ProxyResult tracks bytes transferred and errors during inspection/proxying.
type ProxyResult struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	Err      error `json:"err,omitempty"`
}

// Context gives inspectors access to connection metadata and security callbacks.
type Context interface {
	Context() context.Context
	Service() string
	ClientIP() string
	OnAuthFailure()
	OnSecurityEvent(action, reason string)
}

// Inspector is implemented by each protocol inspection session.
type Inspector interface {
	// Run inspects traffic between client and upstream until session completion.
	// Returns proxy accounting results, whether the session was actively blocked,
	// the reason for blocking (if blocked), and any underlying network error.
	Run(ctx Context, client, upstream net.Conn) (result ProxyResult, blocked bool, reason string, err error)
}

// Manifest defines identity, version, and capabilities of a plugin.
type Manifest struct {
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"version" yaml:"version"`
	Description string   `json:"description" yaml:"description"`
	Author      string   `json:"author,omitempty" yaml:"author,omitempty"`
	Protocols   []string `json:"protocols" yaml:"protocols"`
}

// Plugin is the primary interface that all RouteWarden plugins must implement.
type Plugin interface {
	// Manifest returns the plugin's identity, version, and supported protocols.
	Manifest() Manifest

	// ValidateConfig validates protocol-specific configuration options.
	ValidateConfig(config map[string]any) error

	// CreateInspector creates an inspector instance configured with options.
	CreateInspector(config map[string]any) (Inspector, error)

	// SelfTest executes automated tests (using synthetic in-memory connections like net.Pipe)
	// to verify that the inspector functions properly in the current runtime environment.
	// If SelfTest returns an error, the plugin will be AUTOMATICALLY DISABLED by the engine.
	SelfTest() error
}

// TestResult records the outcome of a plugin's self-test execution.
type TestResult struct {
	PluginName string        `json:"plugin_name"`
	Passed     bool          `json:"passed"`
	Error      error         `json:"error,omitempty"`
	Duration   time.Duration `json:"duration"`
}

// DefaultContext is a helper implementation of Context for tests and standard pipelines.
type DefaultContext struct {
	Ctx             context.Context
	ServiceName     string
	ClientAddress   string
	AuthFailureFunc func()
	SecurityFunc    func(action, reason string)
}

func (d *DefaultContext) Context() context.Context {
	if d.Ctx == nil {
		return context.Background()
	}
	return d.Ctx
}

func (d *DefaultContext) Service() string {
	return d.ServiceName
}

func (d *DefaultContext) ClientIP() string {
	return d.ClientAddress
}

func (d *DefaultContext) OnAuthFailure() {
	if d.AuthFailureFunc != nil {
		d.AuthFailureFunc()
	}
}

func (d *DefaultContext) OnSecurityEvent(action, reason string) {
	if d.SecurityFunc != nil {
		d.SecurityFunc(action, reason)
	}
}
