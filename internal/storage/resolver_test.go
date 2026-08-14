package storage

import (
	"context"
	"testing"
)

// fakeConfigLoader returns a fixed S3Config for "s3org" and empty (local) for
// everyone else.
func fakeConfigLoader(ctx context.Context, orgID string) (S3Config, error) {
	if orgID == "s3org" {
		return S3Config{Bucket: "attachments", AccessKeyID: "AK", SecretAccessKey: "SK", Prefix: "prod"}, nil
	}
	return S3Config{}, nil
}

func TestResolverPerOrgSelection(t *testing.T) {
	local := NewLocalStore(Config{DataDir: t.TempDir(), MaxSize: 1 << 20})
	r := NewResolver(local, fakeConfigLoader, 1<<20, nil)

	ctx := context.Background()

	// Org without S3 → local store.
	s, err := r.Resolve(ctx, "localorg")
	if err != nil {
		t.Fatalf("resolve local: %v", err)
	}
	if s != local {
		t.Errorf("local org: got %T, want local store", s)
	}

	// Org with S3 → S3Store (cached).
	s1, err := r.Resolve(ctx, "s3org")
	if err != nil {
		t.Fatalf("resolve s3: %v", err)
	}
	if _, ok := s1.(*S3Store); !ok {
		t.Fatalf("s3 org: got %T, want *S3Store", s1)
	}
	s2, err := r.Resolve(ctx, "s3org")
	if err != nil {
		t.Fatalf("resolve s3 again: %v", err)
	}
	if s1 != s2 {
		t.Errorf("s3 store not cached: %v != %v", s1, s2)
	}
}
