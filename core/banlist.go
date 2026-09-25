package core

import (
	"context"
	"sync"
	"time"
)

// BanEntry holds metadata for an actively banned IP address.
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Service   string    `json:"service"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

// BanList provides a thread-safe in-memory ban cache with TTL expiration.
type BanList struct {
	mu      sync.RWMutex
	entries map[string]BanEntry
	cancel  context.CancelFunc
}

// NewBanList initializes a new BanList and launches background expiry cleanup.
func NewBanList() *BanList {
	ctx, cancel := context.WithCancel(context.Background())
	bl := &BanList{
		entries: make(map[string]BanEntry),
		cancel:  cancel,
	}

	go bl.cleanupLoop(ctx)
	return bl
}

// Ban records an IP address as banned for the given duration.
func (b *BanList) Ban(ip, reason, service string, duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	var expires time.Time
	perm := duration <= 0
	if !perm {
		expires = now.Add(duration)
	}

	b.entries[ip] = BanEntry{
		IP:        ip,
		Reason:    reason,
		Service:   service,
		BannedAt:  now,
		ExpiresAt: expires,
		Permanent: perm,
	}
}

// Unban removes an IP from the banlist.
func (b *BanList) Unban(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.entries[ip]; exists {
		delete(b.entries, ip)
		return true
	}
	return false
}

// IsBanned returns true and the ban entry if the IP is currently banned and unexpired.
func (b *BanList) IsBanned(ip string) (BanEntry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	entry, ok := b.entries[ip]
	if !ok {
		return BanEntry{}, false
	}

	if !entry.Permanent && time.Now().After(entry.ExpiresAt) {
		return BanEntry{}, false
	}

	return entry, true
}

// All returns a snapshot list of all currently active non-expired bans.
func (b *BanList) All() []BanEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	res := make([]BanEntry, 0, len(b.entries))
	for _, entry := range b.entries {
		if entry.Permanent || now.Before(entry.ExpiresAt) {
			res = append(res, entry)
		}
	}
	return res
}

// Count returns the number of active bans.
func (b *BanList) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

// Close stops background cleanup routines.
func (b *BanList) Close() {
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *BanList) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			now := time.Now()
			for ip, entry := range b.entries {
				if !entry.Permanent && now.After(entry.ExpiresAt) {
					delete(b.entries, ip)
				}
			}
			b.mu.Unlock()
		}
	}
}
