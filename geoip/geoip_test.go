package geoip

import (
	"net"
	"testing"
)

func TestCountryCodeToFlag(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"DE", "🇩🇪"},
		{"FR", "🇫🇷"},
		{"LAN", "🏠"},
		{"VPN", "🔒"},
		{"XX", "🌐"},
		{"INVALID", "🌐"},
	}

	for _, tt := range tests {
		got := CountryCodeToFlag(tt.code)
		if got != tt.expected {
			t.Errorf("CountryCodeToFlag(%q) = %q; expected %q", tt.code, got, tt.expected)
		}
	}
}

func TestIsPrivateOrLocal(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.1.20", true},
		{"192.168.1.1", true},
		{"172.16.0.5", true},
		{"100.64.0.1", true}, // CGNAT
		{"198.51.100.5", true}, // RFC 5737 Test Net
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		parsed := net.ParseIP(tt.ip)
		if parsed == nil {
			t.Fatalf("failed to parse IP %q", tt.ip)
		}
		got := IsPrivateOrLocal(parsed)
		if got != tt.expected {
			t.Errorf("IsPrivateOrLocal(%q) = %v; expected %v", tt.ip, got, tt.expected)
		}
	}
}

func TestLookupIP(t *testing.T) {
	res := LookupIP("127.0.0.1")
	if res.CountryCode != "LAN" {
		t.Errorf("Expected country LAN for 127.0.0.1, got %q", res.CountryCode)
	}
	if !res.IsPrivate {
		t.Errorf("Expected IsPrivate=true for 127.0.0.1")
	}

	resPublic := LookupIP("8.8.8.8")
	if resPublic.IsPrivate {
		t.Errorf("Expected IsPrivate=false for 8.8.8.8")
	}
}
