package plugins

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

// PluginStatus represents the operational health status of a plugin.
type PluginStatus string

const (
	StatusPending  PluginStatus = "PENDING"
	StatusActive   PluginStatus = "ACTIVE"
	StatusDisabled PluginStatus = "DISABLED"
)

// PluginInfo provides human-readable summary of a registered plugin.
type PluginInfo struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Protocols   []string     `json:"protocols"`
	Status      PluginStatus `json:"status"`
	TestError   string       `json:"test_error,omitempty"`
	TestTime    time.Time    `json:"test_time,omitempty"`
}

type entry struct {
	plugin    sdk.Plugin
	status    PluginStatus
	testError error
	testTime  time.Time
}

type Registry struct {
	mu           sync.RWMutex
	plugins      map[string]*entry // keyed by plugin name (lowercase)
	protocolMap  map[string]string // protocol -> plugin name
}

var globalRegistry = NewRegistry()

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins:     make(map[string]*entry),
		protocolMap: make(map[string]string),
	}
}

// Global returns the global singleton registry.
func Global() *Registry {
	return globalRegistry
}

// Register registers a plugin with the global registry.
func Register(p sdk.Plugin) {
	globalRegistry.Register(p)
}

func (r *Registry) Register(p sdk.Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	manifest := p.Manifest()
	nameKey := strings.ToLower(manifest.Name)

	r.plugins[nameKey] = &entry{
		plugin: p,
		status: StatusPending,
	}

	for _, proto := range manifest.Protocols {
		r.protocolMap[strings.ToLower(proto)] = nameKey
	}
}

// RunSelfTests executes SelfTest() on all registered plugins and updates their status.
// If SelfTest fails, status becomes StatusDisabled. If it passes, status becomes StatusActive.
func RunSelfTests() map[string]sdk.TestResult {
	return globalRegistry.RunSelfTests()
}

func (r *Registry) RunSelfTests() map[string]sdk.TestResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	results := make(map[string]sdk.TestResult)

	for name, ent := range r.plugins {
		start := time.Now()
		err := ent.plugin.SelfTest()
		dur := time.Since(start)

		res := sdk.TestResult{
			PluginName: ent.plugin.Manifest().Name,
			Passed:     err == nil,
			Error:      err,
			Duration:   dur,
		}

		ent.testTime = time.Now()
		if err != nil {
			ent.status = StatusDisabled
			ent.testError = err
		} else {
			ent.status = StatusActive
			ent.testError = nil
		}

		results[name] = res
	}

	return results
}

// RunSelfTest runs self test for a single plugin.
func (r *Registry) RunSelfTest(name string) (sdk.TestResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	nameKey := strings.ToLower(name)
	ent, exists := r.plugins[nameKey]
	if !exists {
		return sdk.TestResult{}, fmt.Errorf("plugin %q not found", name)
	}

	start := time.Now()
	err := ent.plugin.SelfTest()
	dur := time.Since(start)

	res := sdk.TestResult{
		PluginName: ent.plugin.Manifest().Name,
		Passed:     err == nil,
		Error:      err,
		Duration:   dur,
	}

	ent.testTime = time.Now()
	if err != nil {
		ent.status = StatusDisabled
		ent.testError = err
	} else {
		ent.status = StatusActive
		ent.testError = nil
	}

	return res, nil
}

// Get finds a plugin by protocol name (e.g. "postgres", "redis").
func Get(protocol string) (sdk.Plugin, bool) {
	return globalRegistry.Get(protocol)
}

func (r *Registry) Get(protocol string) (sdk.Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameKey, ok := r.protocolMap[strings.ToLower(protocol)]
	if !ok {
		return nil, false
	}

	ent, ok := r.plugins[nameKey]
	if !ok {
		return nil, false
	}
	return ent.plugin, true
}

// GetByName finds a plugin by its name.
func GetByName(name string) (sdk.Plugin, bool) {
	return globalRegistry.GetByName(name)
}

func (r *Registry) GetByName(name string) (sdk.Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ent, ok := r.plugins[strings.ToLower(name)]
	if !ok {
		return nil, false
	}
	return ent.plugin, true
}

// IsActive returns true if the plugin exists and passed its self-test.
func IsActive(nameOrProtocol string) bool {
	return globalRegistry.IsActive(nameOrProtocol)
}

func (r *Registry) IsActive(nameOrProtocol string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(nameOrProtocol)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}

	if !ok || ent == nil {
		return false
	}
	return ent.status == StatusActive
}

// GetStatus returns the operational status and any self-test failure reason.
func GetStatus(nameOrProtocol string) (PluginStatus, error) {
	return globalRegistry.GetStatus(nameOrProtocol)
}

func (r *Registry) GetStatus(nameOrProtocol string) (PluginStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(nameOrProtocol)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}

	if !ok || ent == nil {
		return StatusPending, fmt.Errorf("plugin %q not found", nameOrProtocol)
	}
	return ent.status, ent.testError
}

// List returns a sorted list of registered plugin descriptions.
func List() []PluginInfo {
	return globalRegistry.List()
}

func (r *Registry) List() []PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []PluginInfo
	for _, ent := range r.plugins {
		m := ent.plugin.Manifest()
		testErrStr := ""
		if ent.testError != nil {
			testErrStr = ent.testError.Error()
		}
		list = append(list, PluginInfo{
			Name:        m.Name,
			Version:     m.Version,
			Description: m.Description,
			Protocols:   m.Protocols,
			Status:      ent.status,
			TestError:   testErrStr,
			TestTime:    ent.testTime,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	return list
}
