package plugins_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins"
)

func TestInstallPlugin_FromLocalRepo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-install-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "mock_plugin")
	if err := os.MkdirAll(mockPluginDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestContent := `name: mock_plugin
version: 1.2.0
description: A mock plugin for installer testing
protocols:
  - mock_proto
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	pluginGo := `package mock_plugin

import "testing"

func TestMock(t *testing.T) {
	// Passing test
}
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "mock_test.go"), []byte(pluginGo), 0644); err != nil {
		t.Fatal(err)
	}

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/tcp-warden\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin failed: %v", err)
	}

	if res.Name != "mock_plugin" {
		t.Errorf("expected name mock_plugin, got %s", res.Name)
	}
	if !res.TestPassed {
		t.Errorf("expected tests to pass, output: %s", res.TestOutput)
	}
	if res.Status != plugins.StatusActive {
		t.Errorf("expected status ACTIVE, got %v", res.Status)
	}

	// Verify installed entry in plugins.json
	entries, err := plugins.GetInstalledRegistry(tmpDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 installed entry, got %d (err: %v)", len(entries), err)
	}
	if entries[0].Name != "mock_plugin" {
		t.Errorf("expected mock_plugin, got %s", entries[0].Name)
	}

	// Test Uninstall
	if err := plugins.UninstallPlugin("mock_plugin", opts); err != nil {
		t.Fatalf("UninstallPlugin failed: %v", err)
	}

	entriesAfter, _ := plugins.GetInstalledRegistry(tmpDir)
	if len(entriesAfter) != 0 {
		t.Errorf("expected 0 entries after uninstall, got %d", len(entriesAfter))
	}
}

func TestInstallPlugin_FailingTestsDisabled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-install-fail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "broken_plugin")
	_ = os.MkdirAll(mockPluginDir, 0755)

	manifestContent := `name: broken_plugin
version: 0.1.0
description: A plugin with failing tests
protocols:
  - broken_proto
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644)

	brokenTestGo := `package broken_plugin

import "testing"

func TestBroken(t *testing.T) {
	t.Fatalf("intentional assertion failure in plugin test")
}
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "broken_test.go"), []byte(brokenTestGo), 0644)

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/tcp-warden\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin returned unexpected error: %v", err)
	}

	if res.TestPassed {
		t.Errorf("expected tests to fail")
	}
	if res.Status != plugins.StatusDisabled {
		t.Errorf("expected status DISABLED for plugin with failing tests, got %v", res.Status)
	}

	entries, _ := plugins.GetInstalledRegistry(tmpDir)
	if len(entries) != 1 || entries[0].Status != plugins.StatusDisabled {
		t.Errorf("expected registered plugin to have DISABLED status, got %+v", entries)
	}
}

func TestSyncPluginFromSource_UsesCache(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-sync-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockSourceDir := filepath.Join(tmpDir, "source_plugin")
	_ = os.MkdirAll(mockSourceDir, 0755)

	manifestContent := `name: cached_plugin
version: 2.0.0
description: A plugin testing cache retrieval
protocols:
  - cached_proto
`
	_ = os.WriteFile(filepath.Join(mockSourceDir, "plugin.yaml"), []byte(manifestContent), 0644)
	_ = os.WriteFile(filepath.Join(mockSourceDir, "test_test.go"), []byte("package cached_plugin\n\nimport \"testing\"\n\nfunc TestOk(t *testing.T){}\n"), 0644)

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	cacheDir := filepath.Join(tmpDir, "cache")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/tcp-warden\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		CacheDir:   cacheDir,
		NoBuild:    true,
	}

	// First pull: should populate cache
	res1, err := plugins.SyncPluginFromSource("cached_plugin", mockSourceDir, opts)
	if err != nil {
		t.Fatalf("first sync failed: %v", err)
	}
	if !res1.TestPassed {
		t.Errorf("expected test to pass, got: %s", res1.TestOutput)
	}

	// Verify cached files exist
	cachedYaml := filepath.Join(cacheDir, "cached_plugin", "plugin.yaml")
	if _, err := os.Stat(cachedYaml); os.IsNotExist(err) {
		t.Fatalf("expected cached plugin.yaml to exist at %s", cachedYaml)
	}

	// Delete the source to prove second pull uses cache
	_ = os.RemoveAll(mockSourceDir)

	// Second pull: should succeed using cache even though source is gone!
	res2, err := plugins.SyncPluginFromSource("cached_plugin", mockSourceDir, opts)
	if err != nil {
		t.Fatalf("second sync using cache failed: %v", err)
	}
	if res2.Name != "cached_plugin" {
		t.Errorf("expected cached_plugin, got %s", res2.Name)
	}
}

func TestParseGitSource(t *testing.T) {
	tests := []struct {
		input       string
		expectedRepo string
		expectedSub  string
	}{
		{
			input:       "https://github.com/routewarden/plugins/postgres",
			expectedRepo: "https://github.com/routewarden/plugins.git",
			expectedSub:  "postgres",
		},
		{
			input:       "github.com/routewarden/plugins/tree/main/redis",
			expectedRepo: "https://github.com/routewarden/plugins.git",
			expectedSub:  "redis",
		},
		{
			input:       "https://github.com/routewarden/plugins",
			expectedRepo: "https://github.com/routewarden/plugins.git",
			expectedSub:  "",
		},
	}

	for _, tc := range tests {
		repo, sub := plugins.ParseGitSource(tc.input)
		if repo != tc.expectedRepo {
			t.Errorf("input %s: expected repo %s, got %s", tc.input, tc.expectedRepo, repo)
		}
		if sub != tc.expectedSub {
			t.Errorf("input %s: expected sub %s, got %s", tc.input, tc.expectedSub, sub)
		}
	}
}

func TestResolveProjectDir_EnvironmentVariable(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-src-dir-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origEnv := os.Getenv("ROUTEWARDEN_SRC_DIR")
	defer os.Setenv("ROUTEWARDEN_SRC_DIR", origEnv)

	os.Setenv("ROUTEWARDEN_SRC_DIR", tmpDir)
	resolved := plugins.ResolveProjectDir("")
	if resolved != tmpDir {
		t.Errorf("expected %s, got %s", tmpDir, resolved)
	}

	pluginsDir := plugins.ResolvePluginsDir("", resolved)
	expectedPlugins := filepath.Join(tmpDir, "plugins")
	if pluginsDir != expectedPlugins {
		t.Errorf("expected %s, got %s", expectedPlugins, pluginsDir)
	}
}

func TestInstallPlugin_MissingAllGoCreated(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-missing-allgo-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "simple_plugin")
	_ = os.MkdirAll(mockPluginDir, 0755)

	manifestContent := `name: simple_plugin
version: 1.0.0
protocols:
  - simple_proto
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644)
	_ = os.WriteFile(filepath.Join(mockPluginDir, "dummy_test.go"), []byte("package simple_plugin\n"), 0644)

	// Note: target plugins dir does NOT have all/all.go initially
	targetPluginsDir := filepath.Join(tmpDir, "plugins")

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin failed with missing all.go: %v", err)
	}

	if res.Name != "simple_plugin" {
		t.Errorf("expected simple_plugin, got %s", res.Name)
	}

	// Verify all.go was created and has import
	allGoPath := filepath.Join(targetPluginsDir, "all", "all.go")
	content, err := os.ReadFile(allGoPath)
	if err != nil {
		t.Fatalf("expected all.go to be created, err: %v", err)
	}
	if !strings.Contains(string(content), `"github.com/routewarden/tcp-warden/plugins/simple_plugin"`) {
		t.Errorf("expected import in all.go, got: %s", string(content))
	}
}


