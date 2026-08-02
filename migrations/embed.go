// Package migrations embeds the SQL migration files (SPEC §2) so the
// binary can run them at startup via golang-migrate.
package migrations

import "embed"

// FS holds every NNNN_name.up.sql / .down.sql migration file.
//
//go:embed *.sql
var FS embed.FS
