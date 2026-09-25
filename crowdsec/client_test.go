package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestCrowdSecClientSync(t *testing.T) {
	mockResponse := StreamResponse{
		New: []DecisionItem{
			{
				ID:       1,
				Origin:   "cscli",
				Scenario: "manual_ban",
				Scope:    "Ip",
				Type:     "ban",
				Value:    "192.0.2.100",
			},
			{
				ID:       2,
				Origin:   "crowdsec",
				Scenario: "routewarden/tcp-ssh-bf",
				Scope:    "Range",
				Type:     "ban",
				Value:    "198.51.100.0/24",
			},
		},
		Deleted: nil,
	}

	bodyBytes, _ := json.Marshal(mockResponse)

	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			if req.Header.Get("X-Api-Key") != "test-api-key" {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
		}),
	}

	client := NewClient(Config{
		LAPIURL:        "http://mock-crowdsec",
		APIKey:         "test-api-key",
		UpdateInterval: 100 * time.Millisecond,
		HTTPClient:     httpClient,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Start(ctx); err != nil {
		t.Fatalf("failed to start crowdsec client: %v", err)
	}

	// 1. Direct IP check
	dec, ok := client.Check("192.0.2.100")
	if !ok {
		t.Fatalf("expected decision for 192.0.2.100")
	}
	if dec.Action != "ban" || dec.Scenario != "manual_ban" {
		t.Errorf("unexpected decision: %+v", dec)
	}

	// 2. CIDR Range check
	decRange, okRange := client.Check("198.51.100.42")
	if !okRange {
		t.Fatalf("expected decision for 198.51.100.42 within range")
	}
	if decRange.Action != "ban" {
		t.Errorf("expected ban action, got %q", decRange.Action)
	}

	// 3. Unbanned IP check
	_, okClean := client.Check("203.0.113.1")
	if okClean {
		t.Errorf("did not expect decision for clean IP 203.0.113.1")
	}

	ipCount, rangeCount := client.DecisionCount()
	if ipCount != 1 || rangeCount != 1 {
		t.Errorf("expected 1 ip and 1 range decision, got %d and %d", ipCount, rangeCount)
	}
}
