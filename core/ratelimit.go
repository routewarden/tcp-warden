package core

import (
	"sync"
	"time"
)

type tokenBucket struct {
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// RateLimiter manages per-service and per-IP token buckets.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket // key = service:ip
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*tokenBucket),
	}
}

// Allow checks if a connection from ip on service is allowed under limits.
func (r *RateLimiter) Allow(service, ip string, connsPerMin, burst int) bool {
	if connsPerMin <= 0 {
		return true
	}

	capacity := float64(burst)
	if capacity <= 0 {
		capacity = float64(connsPerMin) / 6.0 // default burst
		if capacity < 2 {
			capacity = 2
		}
	}
	refillRate := float64(connsPerMin) / 60.0

	key := service + ":" + ip

	r.mu.Lock()
	defer r.mu.Unlock()

	b, exists := r.buckets[key]
	if !exists {
		b = &tokenBucket{
			tokens:     capacity - 1.0,
			capacity:   capacity,
			refillRate: refillRate,
			lastRefill: time.Now(),
		}
		r.buckets[key] = b
		return true
	}

	return b.allow()
}

// FailureTracker tracks auth failures per IP within a sliding window.
type FailureTracker struct {
	mu       sync.Mutex
	failures map[string][]time.Time // key = service:ip
}

// NewFailureTracker creates a new FailureTracker.
func NewFailureTracker() *FailureTracker {
	return &FailureTracker{
		failures: make(map[string][]time.Time),
	}
}

// RecordFailure records an authentication failure and returns the failure count in the last window.
func (f *FailureTracker) RecordFailure(service, ip string, window time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := service + ":" + ip
	now := time.Now()
	cutoff := now.Add(-window)

	list := f.failures[key]
	valid := make([]time.Time, 0, len(list)+1)
	for _, t := range list {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	f.failures[key] = valid

	return len(valid)
}

// Reset clears failure counts for the given service and IP.
func (f *FailureTracker) Reset(service, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, service+":"+ip)
}
