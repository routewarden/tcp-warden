package main

import (
	"reflect"
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
