package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
)

// BanEntry holds metadata for an actively banned IP address.
type BanEntry struct {
	IP        string    `json:"ip" gorm:"primaryKey;column:ip;size:64"`
	Reason    string    `json:"reason" gorm:"column:reason;not null"`
	Service   string    `json:"service" gorm:"column:service;not null"`
	BannedAt  time.Time `json:"banned_at" gorm:"column:banned_at;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"column:expires_at;index;not null"`
	Permanent bool      `json:"permanent" gorm:"column:permanent;not null"`
}

// TableName explicitly defines the database table name for GORM.
func (BanEntry) TableName() string {
	return "bans"
}

// BanList provides a thread-safe in-memory ban cache with TTL expiration and
// embedded SQLite persistence via GORM. When a dataDir is provided, bans are
// persisted to <dataDir>/bans.db using GORM with WAL mode enabled.
// If a legacy <dataDir>/bans.json file exists, it is automatically migrated into SQLite.
type BanList struct {
	mu      sync.RWMutex
	entries map[string]BanEntry

	// persistence
	dataDir string
	db      *gorm.DB

	cancel context.CancelFunc
}

const (
	dbFilename         = "bans.db"
	legacyJSONFilename = "bans.json"
)

// NewBanList initialises a new BanList with GORM-based embedded SQLite persistence.
// Pass dataDir="" to run purely in memory (no disk I/O).
func NewBanList(dataDir string) *BanList {
	ctx, cancel := context.WithCancel(context.Background())

	bl := &BanList{
		entries: make(map[string]BanEntry),
		dataDir: dataDir,
		cancel:  cancel,
	}

	if dataDir != "" {
		if err := bl.initDB(); err != nil {
			DefaultLogger().Warn("[BanList] SQLite/GORM init error for %s: %v (falling back to memory-only)", dataDir, err)
		} else {
			bl.migrateLegacyJSON()
			bl.load()
		}
	}

	go bl.cleanupLoop(ctx)
	return bl
}

func (b *BanList) initDB() error {
	if err := os.MkdirAll(b.dataDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", b.dataDir, err)
	}

	dbPath := filepath.Join(b.dataDir, dbFilename)
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return fmt.Errorf("open sqlite via gorm %s: %w", dbPath, err)
	}

	// Configure underlying connection pool and pragmas
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
		_, _ = sqlDB.Exec(`
			PRAGMA journal_mode = WAL;
			PRAGMA synchronous = NORMAL;
			PRAGMA busy_timeout = 5000;
		`)
	}

	// Auto-migrate schema with GORM
	if err := db.AutoMigrate(&BanEntry{}); err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}

	b.db = db
	return nil
}

// migrateLegacyJSON imports any existing bans.json into the SQLite database via GORM.
func (b *BanList) migrateLegacyJSON() {
	if b.db == nil || b.dataDir == "" {
		return
	}
	legacyPath := filepath.Join(b.dataDir, legacyJSONFilename)
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return // No legacy file
	}

	var count int64
	b.db.Model(&BanEntry{}).Count(&count)
	if count > 0 {
		return // DB already contains entries, skip migration
	}

	var entries []BanEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		DefaultLogger().Warn("[BanList] corrupt legacy %s: %v", legacyPath, err)
		return
	}

	now := time.Now().UTC()
	var toInsert []BanEntry
	for _, e := range entries {
		if e.Permanent || now.Before(e.ExpiresAt) {
			e.BannedAt = e.BannedAt.UTC()
			e.ExpiresAt = e.ExpiresAt.UTC()
			toInsert = append(toInsert, e)
		}
	}

	if len(toInsert) > 0 {
		err := b.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&toInsert).Error
		if err == nil {
			DefaultLogger().Info("✓  [BanList] migrated %d ban(s) from legacy %s into SQLite via GORM", len(toInsert), legacyPath)
			_ = os.Rename(legacyPath, legacyPath+".migrated.bak")
		} else {
			DefaultLogger().Warn("[BanList] GORM migration error: %v", err)
		}
	}
}

// load reads active bans from SQLite via GORM into the in-memory cache.
func (b *BanList) load() {
	if b.db == nil {
		return
	}

	now := time.Now().UTC()
	var records []BanEntry
	err := b.db.Where("permanent = ? OR expires_at > ?", true, now).Find(&records).Error
	if err != nil {
		DefaultLogger().Warn("[BanList] GORM query bans error: %v", err)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, e := range records {
		b.entries[e.IP] = e
	}

	if len(records) > 0 {
		DefaultLogger().Info("✓  [BanList] loaded %d active ban(s) from SQLite (%s)", len(records), filepath.Join(b.dataDir, dbFilename))
	}
}

// Ban records an IP address as banned for the given duration.
// Pass duration <= 0 for a permanent ban.
func (b *BanList) Ban(ip, reason, service string, duration time.Duration) {
	now := time.Now().UTC()
	perm := duration <= 0
	var expires time.Time
	if !perm {
		expires = now.Add(duration)
	}

	entry := BanEntry{
		IP:        ip,
		Reason:    reason,
		Service:   service,
		BannedAt:  now,
		ExpiresAt: expires,
		Permanent: perm,
	}

	b.mu.Lock()
	b.entries[ip] = entry
	b.mu.Unlock()

	if b.db != nil {
		err := b.db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&entry).Error
		if err != nil {
			DefaultLogger().Warn("[BanList] GORM upsert error for %s: %v", ip, err)
		}
	}
}

// Unban removes an IP from the banlist. Returns true if the IP was present.
func (b *BanList) Unban(ip string) bool {
	b.mu.Lock()
	_, exists := b.entries[ip]
	if exists {
		delete(b.entries, ip)
	}
	b.mu.Unlock()

	if b.db != nil {
		tx := b.db.Where("ip = ?", ip).Delete(&BanEntry{})
		if tx.Error != nil {
			DefaultLogger().Warn("[BanList] GORM delete error for %s: %v", ip, tx.Error)
		} else if !exists && tx.RowsAffected > 0 {
			exists = true
		}
	}
	return exists
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

// All returns a snapshot of all currently active (non-expired) bans.
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

// Count returns the number of currently active (non-expired) bans.
func (b *BanList) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, entry := range b.entries {
		if entry.Permanent || now.Before(entry.ExpiresAt) {
			count++
		}
	}
	return count
}

// Close stops background routines and closes the underlying SQLite database connection.
func (b *BanList) Close() {
	if b.cancel != nil {
		b.cancel()
	}
	if b.db != nil {
		if sqlDB, err := b.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
}

// cleanupLoop periodically removes expired entries from memory and SQLite via GORM.
func (b *BanList) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()

			b.mu.Lock()
			for ip, entry := range b.entries {
				if !entry.Permanent && now.After(entry.ExpiresAt) {
					delete(b.entries, ip)
				}
			}
			b.mu.Unlock()

			if b.db != nil {
				if err := b.db.Where("permanent = ? AND expires_at <= ?", false, now).Delete(&BanEntry{}).Error; err != nil {
					DefaultLogger().Warn("[BanList] GORM prune error: %v", err)
				}
			}
		}
	}
}
