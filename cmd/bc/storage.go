package main

import (
	"context"
	"log/slog"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/storage"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// storageMigrate migrates attachment objects from the local store to the S3
// store configured for a given org (WU-506 migration helper). It reads the
// org's S3 config from org_secrets, copies every attachment object preserving
// keys, and verifies each copy by checksum.
func storageMigrate(ctx context.Context, cfg *config.Config, orgID string) {
	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		slog.Error("storage migrate: open db", "error", err)
		return
	}
	defer conn.Close()
	q := sqlc.New(conn)

	// Read the org's S3 config from org_secrets.
	secret, err := q.FindOrgSecretByKey(ctx, sqlc.FindOrgSecretByKeyParams{OrgID: orgID, Key: "s3_config"})
	if err != nil {
		slog.Error("storage migrate: no s3 config for org", "org", orgID, "error", err)
		return
	}
	plain, err := tenant.Decrypt(tenant.PadKey(cfg.SecretKey), secret.Ciphertext)
	if err != nil {
		slog.Error("storage migrate: decrypt config", "error", err)
		return
	}
	s3cfg, err := storage.ParseS3Config([]byte(plain))
	if err != nil {
		slog.Error("storage migrate: parse config", "error", err)
		return
	}

	client, err := storage.NewS3Client(s3cfg)
	if err != nil {
		slog.Error("storage migrate: s3 client", "error", err)
		return
	}
	dst, err := storage.NewS3Store(client, s3cfg, 10<<20, nil)
	if err != nil {
		slog.Error("storage migrate: s3 store", "error", err)
		return
	}
	src := storage.NewLocalStore(storage.Config{DataDir: cfg.DataDir})

	// Enumerate storage keys for the org.
	keys, err := listStorageKeys(ctx, q, orgID)
	if err != nil {
		slog.Error("storage migrate: list keys", "error", err)
		return
	}

	res, err := storage.MigrateLocalToS3(ctx, src, dst, keys)
	if err != nil {
		slog.Error("storage migrate: migrate", "error", err)
		return
	}
	slog.Info("storage migrate done",
		"org", orgID, "copied", res.Copied, "skipped", res.Skipped,
		"verified", res.Verified, "failed", len(res.Failed))
	for _, k := range res.Failed {
		slog.Warn("storage migrate: failed key", "key", k)
	}
}

// listStorageKeys returns the storage_key of every attachment in the org.
func listStorageKeys(ctx context.Context, q *sqlc.Queries, orgID string) ([]string, error) {
	rows, err := q.ListAttachmentsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(rows))
	for _, a := range rows {
		if a.StorageKey != "" {
			keys = append(keys, a.StorageKey)
		}
	}
	return keys, nil
}
