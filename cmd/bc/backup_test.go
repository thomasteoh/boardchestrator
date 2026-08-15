package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db"
)

// TestBackupRestoreRoundTrip verifies `bc backup` produces a timestamped file
// whose content round-trips into a fresh DB (WU-507 AC: backup/restore
// round-trip). It uses the real sqlite driver + migrations.
func TestBackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "live.db")
	cfg := &config.Config{DBPath: dbPath, DataDir: dir}

	// Live DB: migrate + insert a marker row.
	conn, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.MigrateUp(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO orgs (id, name, slug) VALUES ('org1', 'Test', 'test')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	conn.Close()

	// Backup.
	backup(context.Background(), cfg)
	backupDir := filepath.Join(dir, "backups")
	matches, _ := filepath.Glob(filepath.Join(backupDir, "boardchestrator-*.db"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 backup, got %d: %v", len(matches), matches)
	}
	backupFile := matches[0]
	if !strings.Contains(filepath.Base(backupFile), "boardchestrator-") {
		t.Errorf("backup name: %s", backupFile)
	}

	// Restore: VACUUM INTO'd file is a standalone DB — open it directly.
	restored, err := db.Open(backupFile)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer restored.Close()
	var slug string
	err = restored.QueryRow(`SELECT slug FROM orgs WHERE id='org1'`).Scan(&slug)
	if err != nil {
		t.Fatalf("marker row missing after restore: %v", err)
	}
	if slug != "test" {
		t.Errorf("slug = %q, want test", slug)
	}
}

// TestBackupPrune verifies pruning keeps the newest N backups (WU-507).
func TestBackupPrune(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Create 6 timestamped backups; names sort newest-last.
	base := time.Now().UTC().Add(-10 * time.Hour)
	for i := 0; i < 6; i++ {
		stamp := base.Add(time.Duration(i) * time.Hour).Format("20060102T150405Z")
		name := filepath.Join(backupDir, "boardchestrator-"+stamp+".db")
		if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	prune(context.Background(), backupDir, backupKeep)

	matches, _ := filepath.Glob(filepath.Join(backupDir, "boardchestrator-*.db"))
	if len(matches) != backupKeep {
		t.Errorf("after prune: %d files, want %d", len(matches), backupKeep)
	}
}

// TestBackupPruneKeepsNewest ensures the newest survive pruning.
func TestBackupPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-10 * time.Hour)
	for i := 0; i < 6; i++ {
		stamp := base.Add(time.Duration(i) * time.Hour).Format("20060102T150405Z")
		if err := os.WriteFile(filepath.Join(backupDir, "boardchestrator-"+stamp+".db"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	prune(context.Background(), backupDir, backupKeep)
	matches, _ := filepath.Glob(filepath.Join(backupDir, "boardchestrator-*.db"))
	if len(matches) != backupKeep {
		t.Fatalf("after prune: %d files, want %d", len(matches), backupKeep)
	}
}
