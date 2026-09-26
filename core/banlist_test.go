package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBanList_Memory(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	if bl.Count() != 0 {
		t.Fatalf("expected 0 bans, got %d", bl.Count())
	}

	bl.Ban("1.2.3.4", "test_reason", "ssh", 1*time.Hour)
	if bl.Count() != 1 {
		t.Fatalf("expected 1 ban, got %d", bl.Count())
	}

	entry, ok := bl.IsBanned("1.2.3.4")
	if !ok || entry.IP != "1.2.3.4" || entry.Reason != "test_reason" {
		t.Fatalf("unexpected ban entry: %+v", entry)
	}

	if !bl.Unban("1.2.3.4") {
		t.Fatal("expected unban to succeed")
	}
	if bl.Count() != 0 {
		t.Fatalf("expected 0 bans after unban, got %d", bl.Count())
	}
}

func TestBanList_SQLitePersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "banlist-sqlite-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Create BanList, add permanent and timed bans
	bl := NewBanList(tmpDir)
	bl.Ban("10.0.0.1", "brute_force", "ssh", 0) // permanent
	bl.Ban("10.0.0.2", "port_scan", "redis", 2*time.Hour)
	bl.Close()

	// Verify db file exists
	dbFile := filepath.Join(tmpDir, "bans.db")
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		t.Fatalf("expected bans.db file at %s", dbFile)
	}

	// Step 2: Re-open BanList on same directory (simulating restart)
	bl2 := NewBanList(tmpDir)
	defer bl2.Close()

	if bl2.Count() != 2 {
		t.Fatalf("expected 2 reloaded bans, got %d", bl2.Count())
	}

	e1, ok1 := bl2.IsBanned("10.0.0.1")
	if !ok1 || !e1.Permanent || e1.Reason != "brute_force" {
		t.Fatalf("unexpected reloaded entry for 10.0.0.1: %+v", e1)
	}

	e2, ok2 := bl2.IsBanned("10.0.0.2")
	if !ok2 || e2.Permanent || e2.Service != "redis" {
		t.Fatalf("unexpected reloaded entry for 10.0.0.2: %+v", e2)
	}

	// Step 3: Unban in bl2 and restart again to ensure deletion persisted
	if !bl2.Unban("10.0.0.2") {
		t.Fatal("expected unban to succeed")
	}
	bl2.Close()

	bl3 := NewBanList(tmpDir)
	defer bl3.Close()

	if bl3.Count() != 1 {
		t.Fatalf("expected 1 ban after deletion and restart, got %d", bl3.Count())
	}
	if _, ok := bl3.IsBanned("10.0.0.2"); ok {
		t.Fatal("expected 10.0.0.2 to remain unbanned across restarts")
	}
}

func TestBanList_LegacyJSONMigration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "banlist-migration-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create legacy bans.json file
	legacyEntries := []BanEntry{
		{
			IP:        "192.168.1.100",
			Reason:    "legacy_perm_ban",
			Service:   "ssh",
			BannedAt:  time.Now().Add(-1 * time.Hour),
			Permanent: true,
		},
		{
			IP:        "192.168.1.101",
			Reason:    "legacy_timed_ban",
			Service:   "postgres",
			BannedAt:  time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Hour),
			Permanent: false,
		},
		{
			IP:        "192.168.1.102",
			Reason:    "legacy_expired_ban",
			Service:   "redis",
			BannedAt:  time.Now().Add(-5 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			Permanent: false,
		},
	}

	data, err := json.Marshal(legacyEntries)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "bans.json"), data, 0o644); err != nil {
		t.Fatalf("write bans.json error: %v", err)
	}

	// Initialize BanList on the folder
	bl := NewBanList(tmpDir)
	defer bl.Close()

	// 100 (perm) and 101 (timed, active) should be imported; 102 (expired) should be skipped
	if bl.Count() != 2 {
		t.Fatalf("expected 2 migrated bans, got %d", bl.Count())
	}

	if _, ok := bl.IsBanned("192.168.1.100"); !ok {
		t.Fatal("expected 192.168.1.100 to be banned")
	}
	if _, ok := bl.IsBanned("192.168.1.101"); !ok {
		t.Fatal("expected 192.168.1.101 to be banned")
	}
	if _, ok := bl.IsBanned("192.168.1.102"); ok {
		t.Fatal("expected expired ban 192.168.1.102 to NOT be imported")
	}
}
