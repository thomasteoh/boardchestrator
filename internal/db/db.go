// Package db opens the SQLite database with the connection settings
// required by the spec (WAL, foreign keys, busy timeout) and applies the
// embedded migrations.
package db

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/thomasteoh/boardchestrator/migrations"
)

// Open opens (creating if needed) the SQLite database at path. Pragmas are
// carried in the DSN so every pooled connection gets them: WAL journal
// mode, enforced foreign keys, 5s busy timeout, NORMAL synchronous (safe
// under WAL).
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)",
		path,
	)
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	if err := d.Ping(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ping sqlite %q: %w", path, err)
	}
	return d, nil
}

// MigrateUp applies all pending embedded migrations. A database that is
// already up to date is not an error, so it is safe to run at every startup.
func MigrateUp(d *sql.DB) error {
	m, err := newMigrator(d)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// MigrateDown reverts every applied migration. It exists to prove down
// migrations round-trip in tests; runtime code never calls it.
func MigrateDown(d *sql.DB) error {
	m, err := newMigrator(d)
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

func newMigrator(d *sql.DB) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}
	drv, err := migratesqlite.WithInstance(d, &migratesqlite.Config{})
	if err != nil {
		return nil, fmt.Errorf("init migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", drv)
	if err != nil {
		return nil, fmt.Errorf("init migrator: %w", err)
	}
	return m, nil
}
