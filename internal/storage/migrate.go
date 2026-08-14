package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// MigrateResult reports the outcome of a local→S3 migration.
type MigrateResult struct {
	Copied   int      // objects copied to S3
	Skipped  int      // objects already present (same checksum)
	Verified int      // objects verified by checksum
	Failed   []string // storage keys that failed to copy
}

// MigrateLocalToS3 copies every attachment object from local into the S3
// store, preserving storage keys, and verifies each copy by checksum (WU-506
// AC: migrate helper moves + verifies checksums). src must be a *LocalStore and
// dst an *S3Store. keys enumerates the storage keys to migrate.
func MigrateLocalToS3(ctx context.Context, src *LocalStore, dst *S3Store, keys []string) (*MigrateResult, error) {
	res := &MigrateResult{}
	for _, key := range keys {
		rc, err := src.Open(ctx, key)
		if err != nil {
			res.Failed = append(res.Failed, key)
			continue
		}
		data, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			res.Failed = append(res.Failed, key)
			continue
		}

		// Skip if the object already exists with a matching checksum.
		sum := sha256.Sum256(data)
		got, cerr := dst.Checksum(ctx, key)
		if cerr == nil && got == hex.EncodeToString(sum[:]) {
			res.Skipped++
			continue
		}

		// Copy, then verify.
		if err := dst.putKey(ctx, key, data, ContentType(key)); err != nil {
			res.Failed = append(res.Failed, key)
			continue
		}
		res.Copied++
		got, err = dst.Checksum(ctx, key)
		if err != nil {
			res.Failed = append(res.Failed, key)
			continue
		}
		if got == hex.EncodeToString(sum[:]) {
			res.Verified++
		} else {
			res.Failed = append(res.Failed, key)
		}
	}
	return res, nil
}
