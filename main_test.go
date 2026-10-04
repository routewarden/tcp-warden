package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/config"
)

func TestNormalizeArgs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "flags after positional arg",
			input:    []string{"198.51.100.42", "--duration", "2h", "--reason", "brute_force"},
			expected: []string{"--duration", "2h", "--reason", "brute_force", "198.51.100.42"},
		},
		{
			name:     "boolean flags with positional",
			input:    []string{"my-plugin", "--force", "--no-build", "--no-service"},
			expected: []string{"--force", "--no-build", "--no-service", "my-plugin"},
		},
		{
			name:     "flags before positional",
			input:    []string{"--config", "custom.yaml", "postgres"},
			expected: []string{"--config", "custom.yaml", "postgres"},
		},
		{
			name:     "equal sign flags",
			input:    []string{"10.0.0.1", "--api=http://127.0.0.1:9091"},
			expected: []string{"--api=http://127.0.0.1:9091", "10.0.0.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := normalizeArgs(tc.input)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("expected %v, got %v", tc.expected, actual)
			}
		})
	}
}

func TestVersionMatchesJSON(t *testing.T) {
	data, err := os.ReadFile("version.json")
	if err != nil {
		t.Fatalf("failed to read version.json: %v", err)
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to parse version.json: %v", err)
	}
	expected := strings.TrimPrefix(v.Version, "v")
	if version != expected {
		t.Errorf("main.go version (%q) does not match version.json (%q). Run ./scripts/update-version.sh", version, expected)
	}
}

func TestResolveConfigPath(t *testing.T) {
	// 1. Explicit custom path
	if p := resolveConfigPath("/custom/path.yaml"); p != "/custom/path.yaml" {
		t.Errorf("expected /custom/path.yaml, got %s", p)
	}

	// 2. ROUTEWARDEN_CONFIG env var
	t.Setenv("ROUTEWARDEN_CONFIG", "/env/path.yaml")
	if p := resolveConfigPath(""); p != "/env/path.yaml" {
		t.Errorf("expected /env/path.yaml, got %s", p)
	}
	t.Setenv("ROUTEWARDEN_CONFIG", "")

	// 3. Local fallback when no env var and no container dir
	if p := resolveConfigPath(""); p != "tcp-warden.yaml" {
		t.Errorf("expected tcp-warden.yaml, got %s", p)
	}
}

func TestUninstalledPluginConfigDoesNotCrash(t *testing.T) {
	yamlContent := `version: "1.0"
services:
  postgres:
    listen: ":15432"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
`
	tmp, err := os.CreateTemp("", "test-postgres-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if err := os.WriteFile(tmp.Name(), []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// We need config package to load
	// In root package, we can parse or load via config.Load
	cfg, err := resolveAndLoad(tmp.Name())
	if err != nil {
		t.Fatalf("expected config to load without error/crash, got: %v", err)
	}

	if len(cfg.Warnings) == 0 {
		t.Errorf("expected warnings about uninstalled/disabled plugin, got none")
	}

	foundWarning := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "postgres") && strings.Contains(w, "requires plugin") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected warning mentioning postgres plugin requirement, got: %v", cfg.Warnings)
	}
}

func resolveAndLoad(path string) (*config.Config, error) {
	return config.Load(path)
}

// ── Bug #9: truncate must operate on Unicode codepoints (runes), not raw bytes ──

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hell…"},
		{"exact", 5, "exact"},
		{"", 5, ""},
		// Multi-byte Unicode: "你好世界" (4 Chinese characters, 12 bytes)
		{"你好世界", 3, "你好…"},
		// Multi-byte Unicode: emojis (4 bytes per codepoint in UTF-8)
		{"🔒🔑🎁🚀", 3, "🔒🔑…"},
	}

	for _, tc := range tests {
		actual := truncate(tc.input, tc.maxLen)
		if actual != tc.expected {
			t.Errorf("truncate(%q, %d): expected %q, got %q", tc.input, tc.maxLen, tc.expected, actual)
		}
		// In terms of runes: length should never exceed maxLen
		if runeCount := len([]rune(actual)); runeCount > tc.maxLen {
			t.Errorf("truncate(%q, %d) produced %d runes, which exceeds maxLen %d", tc.input, tc.maxLen, runeCount, tc.maxLen)
		}
	}
}


