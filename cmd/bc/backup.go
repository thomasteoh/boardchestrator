package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db"
)

// backupKeep is the default number of backup files to keep (prune to N).
const backupKeep = 5

// backup runs `VACUUM INTO` against the live DB to produce a timestamped
// backup file, then prunes old backups to the newest N (WU-507). Backups are
// written to <DataDir>/backups/.
func backup(ctx context.Context, cfg *config.Config) {
	dir := filepath.Join(cfg.DataDir, "backups")
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("backup: mkdir", "error", err)
		return
	}

	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		slog.Error("backup: open db", "error", err)
		return
	}
	defer conn.Close()

	// VACUUM INTO produces a standalone, fully-consistent snapshot of the DB.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join(dir, fmt.Sprintf("boardchestrator-%s.db", stamp))
	// Use a query parameter to safely quote the absolute path for the SQL.
	quoted := strings.ReplaceAll(out, "'", "''")
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s'", quoted)); err != nil {
		slog.Error("backup: vacuum into", "error", err)
		return
	}
	slog.Info("backup created", "file", out)

	prune(ctx, dir, backupKeep)
}

// prune deletes the oldest backup files beyond the newest N, keeping the most
// recent keep files.
func prune(ctx context.Context, dir string, keep int) {
	matches, err := filepath.Glob(filepath.Join(dir, "boardchestrator-*.db"))
	if err != nil {
		slog.Error("backup: glob", "error", err)
		return
	}
	if len(matches) <= keep {
		return
	}
	// Sort by name (timestamp) descending so the newest are first.
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, m := range matches[keep:] {
		if err := os.Remove(m); err != nil {
			slog.Warn("backup: prune", "file", m, "error", err)
		} else {
			slog.Info("backup pruned", "file", m)
		}
	}
}
