package storage

import (
	"context"
	"strings"
	"testing"
)

func TestMigrateLocalToS3(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	local := NewLocalStore(Config{DataDir: dir, MaxSize: 1 << 20})
	f := newFakeS3API()
	s3s, err := NewS3Store(f, S3Config{Bucket: "attachments", AccessKeyID: "AK", SecretAccessKey: "SK", Prefix: "prod"}, 1<<20, nil)
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	// Upload two files to local.
	keys := []string{}
	for _, fname := range []string{"a.png", "b.png"} {
		_, key, err := local.Upload(ctx, fname, []byte("content-"+fname), "org1", "task1")
		if err != nil {
			t.Fatalf("local upload: %v", err)
		}
		keys = append(keys, key)
	}

	// Migrate local→S3.
	res, err := MigrateLocalToS3(ctx, local, s3s, keys)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if res.Copied != 2 {
		t.Errorf("copied = %d, want 2", res.Copied)
	}
	if res.Verified != 2 {
		t.Errorf("verified = %d, want 2", res.Verified)
	}
	if len(res.Failed) != 0 {
		t.Errorf("failed = %v, want none", res.Failed)
	}

	// Keys preserved (object keys are prefix + storage key).
	for _, k := range keys {
		if _, ok := f.objects["prod/"+k]; !ok {
			t.Errorf("object %q not in S3", k)
		}
	}

	// Re-run: everything skipped (same checksum), verified.
	res2, err := MigrateLocalToS3(ctx, local, s3s, keys)
	if err != nil {
		t.Fatalf("migrate2: %v", err)
	}
	if res2.Skipped != 2 {
		t.Errorf("skipped = %d, want 2", res2.Skipped)
	}
	if res2.Copied != 0 {
		t.Errorf("copied on re-run = %d, want 0", res2.Copied)
	}
}

func TestMigrateLocalToS3MissingKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	local := NewLocalStore(Config{DataDir: dir, MaxSize: 1 << 20})
	f := newFakeS3API()
	s3s, err := NewS3Store(f, S3Config{Bucket: "attachments", AccessKeyID: "AK", SecretAccessKey: "SK"}, 1<<20, nil)
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	res, err := MigrateLocalToS3(ctx, local, s3s, []string{"nonexistent/key"})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(res.Failed) != 1 {
		t.Errorf("failed = %v, want the missing key", res.Failed)
	}
	if !strings.HasPrefix(res.Failed[0], "nonexistent") {
		t.Errorf("failed key = %q", res.Failed[0])
	}
}
