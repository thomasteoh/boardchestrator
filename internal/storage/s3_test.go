package storage

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3API is an in-memory S3 API fake used to test S3Store without a live
// server (WU-506 AC: test against a fake or SDK middleware stub).
type fakeS3API struct {
	objects map[string][]byte
	mime    map[string]string
}

func newFakeS3API() *fakeS3API {
	return &fakeS3API{objects: map[string][]byte{}, mime: map[string]string{}}
}

func (f *fakeS3API) PutObject(ctx context.Context, input *s3.PutObjectInput, opt ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*input.Key] = data
	if input.ContentType != nil {
		f.mime[*input.Key] = *input.ContentType
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3API) GetObject(ctx context.Context, input *s3.GetObjectInput, opt ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	data, ok := f.objects[*input.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(string(data)))}, nil
}

func (f *fakeS3API) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput, opt ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(f.objects, *input.Key)
	delete(f.mime, *input.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (f *fakeS3API) HeadObject(ctx context.Context, input *s3.HeadObjectInput, opt ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if _, ok := f.objects[*input.Key]; !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.HeadObjectOutput{}, nil
}

func TestS3ConfigRoundTrip(t *testing.T) {
	cfg := S3Config{
		Endpoint:        "http://localhost:9000",
		Region:          "",
		Bucket:          "attachments",
		AccessKeyID:     "AK",
		SecretAccessKey: "SK",
		PathStyle:       true,
		Prefix:          "prod",
	}
	data, err := S3ConfigJSON(cfg)
	if err != nil {
		t.Fatalf("S3ConfigJSON: %v", err)
	}
	got, err := ParseS3Config(data)
	if err != nil {
		t.Fatalf("ParseS3Config: %v", err)
	}
	if got != cfg {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, cfg)
	}
}

func TestS3StoreUploadOpenDelete(t *testing.T) {
	f := newFakeS3API()
	store, err := NewS3Store(f, S3Config{Bucket: "attachments", AccessKeyID: "AK", SecretAccessKey: "SK", Prefix: "prod"}, 1<<20, nil)
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	ctx := context.Background()
	id, key, err := store.Upload(ctx, "test.png", []byte("hello world"), "org1", "task1")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if id == "" || key == "" {
		t.Fatalf("empty id/key")
	}
	// Object stored under prefix + key with correct MIME.
	objKey := "prod/" + key
	if got := string(f.objects[objKey]); got != "hello world" {
		t.Errorf("object content = %q, want hello world", got)
	}
	if got := f.mime[objKey]; got != "image/png" {
		t.Errorf("mime = %q, want image/png", got)
	}

	// Open and verify.
	rc, err := store.Open(ctx, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "hello world" {
		t.Errorf("Open content = %q", got)
	}

	// Checksum (SHA-256) of the stored object.
	sum, err := store.Checksum(ctx, key)
	if err != nil {
		t.Fatalf("Checksum: %v", err)
	}
	if sum == "" || len(sum) != 64 {
		t.Errorf("checksum = %q, want 64-hex", sum)
	}

	// Delete removes it.
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := f.objects[objKey]; ok {
		t.Errorf("object still present after delete")
	}
}

func TestS3StoreSizeLimit(t *testing.T) {
	f := newFakeS3API()
	store, err := NewS3Store(f, S3Config{Bucket: "b", AccessKeyID: "AK", SecretAccessKey: "SK"}, 100, nil)
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	_, _, err = store.Upload(context.Background(), "big.bin", make([]byte, 200), "o", "t")
	if err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestS3StoreRejectsBadType(t *testing.T) {
	f := newFakeS3API()
	store, err := NewS3Store(f, S3Config{Bucket: "b", AccessKeyID: "AK", SecretAccessKey: "SK"}, 1<<20, []string{"text/plain"})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	_, _, err = store.Upload(context.Background(), "bad.png", []byte("bad"), "o", "t")
	if err == nil {
		t.Fatal("expected content-type rejection")
	}
}

func TestS3StoreConfigValidate(t *testing.T) {
	c0 := S3Config{}
	if err := c0.Validate(); err == nil {
		t.Fatal("empty config should fail validation")
	}
	c := S3Config{Bucket: "b", AccessKeyID: "AK", SecretAccessKey: ""}
	if err := c.Validate(); err == nil {
		t.Fatal("missing secret should fail validation")
	}
}

func TestS3StoreSanitisesSVG(t *testing.T) {
	f := newFakeS3API()
	store, err := NewS3Store(f, S3Config{Bucket: "b", AccessKeyID: "AK", SecretAccessKey: "SK"}, 1<<20, nil)
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><text>hi</text></svg>`
	_, _, err = store.Upload(context.Background(), "x.svg", []byte(svg), "o", "t")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	got := string(f.objects["x.svg"])
	if strings.Contains(got, "<script>") {
		t.Errorf("script not stripped: %q", got)
	}
}
