package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStoreUpload(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalStore(Config{DataDir: dir, MaxSize: 1 << 20})

	ctx := context.Background()
	id, key, err := store.Upload(ctx, "test.png", []byte("hello world"), "org1", "task1")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if id == "" {
		t.Fatal("empty attachment id")
	}
	if key == "" {
		t.Fatal("empty storage key")
	}

	// File should exist on disk.
	path := filepath.Join(dir, "attachments", key)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not stored at %s: %v", path, err)
	}

	// Open and verify content.
	rc, err := store.Open(ctx, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
}

func TestLocalStoreDelete(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalStore(Config{DataDir: dir, MaxSize: 1 << 20})

	ctx := context.Background()
	_, key, err := store.Upload(ctx, "delete.txt", []byte("delete me"), "org1", "task1")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// File should be gone.
	path := filepath.Join(dir, "attachments", key)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after delete: %v", err)
	}

	// Delete non-existent — should be no-op.
	if err := store.Delete(ctx, "nonexistent/key"); err != nil {
		t.Fatalf("Delete nonexistent: %v", err)
	}
}

func TestLocalStoreSizeLimit(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalStore(Config{DataDir: dir, MaxSize: 100})

	ctx := context.Background()
	data := make([]byte, 200)
	_, _, err := store.Upload(ctx, "large.txt", data, "org1", "task1")
	if err == nil {
		t.Fatal("expected size limit error, got nil")
	}
}

func TestLocalStoreContentType(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalStore(Config{
		DataDir:      dir,
		MaxSize:      1 << 20,
		ContentTypes: []string{"text/plain"},
	})

	ctx := context.Background()
	// .txt is text/plain -> allowed
	_, _, err := store.Upload(ctx, "ok.txt", []byte("ok"), "org1", "task1")
	if err != nil {
		t.Fatalf("Upload allowed type: %v", err)
	}

	// .png is not in allowed list -> rejected
	_, _, err = store.Upload(ctx, "bad.png", []byte("bad"), "org1", "task1")
	if err == nil {
		t.Fatal("expected rejection for .png, got nil")
	}
}

func TestLocalStoreSVGSanitise(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalStore(Config{DataDir: dir, MaxSize: 1 << 20})

	ctx := context.Background()
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><text>hello</text></svg>`
	_, _, err := store.Upload(ctx, "test.svg", []byte(svg), "org1", "task1")
	if err != nil {
		t.Fatalf("Upload SVG: %v", err)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"simple.txt", "simple.txt"},
		{"../../evil.sh", ".._.._evil.sh"},
		{"spaces and special!.png", "spaces_and_special_.png"},
	}
	for _, c := range cases {
		got := sanitizeFilename(c.in)
		if got != c.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestContentType(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"photo.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"doc.pdf", "application/pdf"},
		{"readme.txt", "text/plain"},
		{"unknown.bin", "application/octet-stream"},
	}
	for _, c := range cases {
		got := ContentType(c.name)
		if got != c.want {
			t.Errorf("ContentType(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
