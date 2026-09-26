package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
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
			input:    []string{"my-plugin", "--force", "--no-build"},
			expected: []string{"--force", "--no-build", "my-plugin"},
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

