// Package storage defines the attachment storage interface and provides
// a local-filesystem backend. See SPEC §9.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config is the per-org S3 storage backend configuration. It is stored
// encrypted in org_secrets (key "s3_config") and round-trips as JSON.
type S3Config struct {
	Endpoint        string `json:"endpoint"`          // custom S3-compatible endpoint (e.g. MinIO)
	Region          string `json:"region"`            // region ("" ok for path-style custom endpoints)
	Bucket          string `json:"bucket"`            // bucket name
	AccessKeyID     string `json:"access_key_id"`     // access key
	SecretAccessKey string `json:"secret_access_key"` // secret key (encrypted at rest)
	PathStyle       bool   `json:"path_style"`        // true for MinIO/custom endpoints
	Prefix          string `json:"prefix,omitempty"`  // optional key prefix under bucket
}

// Validate checks required fields are present.
func (c *S3Config) Validate() error {
	if c.Bucket == "" {
		return fmt.Errorf("s3: bucket required")
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return fmt.Errorf("s3: access key and secret required")
	}
	return nil
}

// MarshalJSON/UnmarshalJSON are provided implicitly; round-trip is stable
// because all fields are exported and tagged.

// s3API is the narrow surface the S3 store needs, so tests can substitute a
// fake. It mirrors the AWS SDK v2 PutObject/GetObject/DeleteObject/HeadObject
// operations with the exact signatures we use.
type s3API interface {
	PutObject(ctx context.Context, input *s3.PutObjectInput, opt ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, input *s3.GetObjectInput, opt ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, input *s3.DeleteObjectInput, opt ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, input *s3.HeadObjectInput, opt ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// S3Store implements Store on an S3-compatible bucket (AWS SDK v2). It uses a
// custom endpoint with an optional path-style addressing mode for MinIO-style
// stores. Validation and processing (size/type, image re-encode, SVG
// sanitisation) mirror LocalStore.
type S3Store struct {
	api     s3API
	bucket  string
	prefix  string
	maxSize int64
	allowed map[string]bool
}

// NewS3Store creates an S3Store backed by the given client wrapper. cfg is the
// S3Config (endpoint/region/bucket/keys/path-style). maxSize is the per-file
// size limit; contentTypes restricts allowed MIME types (defaults same as
// LocalStore when empty).
func NewS3Store(client s3API, cfg S3Config, maxSize int64, contentTypes []string) (*S3Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if maxSize == 0 {
		maxSize = 10 << 20 // 10MB
	}
	allowed := make(map[string]bool)
	for _, t := range contentTypes {
		allowed[t] = true
	}
	if len(allowed) == 0 {
		for _, t := range []string{
			"image/png", "image/jpeg", "image/gif", "image/webp",
			"application/pdf", "text/plain", "text/csv",
			"application/json", "application/octet-stream",
			"image/svg+xml",
		} {
			allowed[t] = true
		}
	}
	prefix := strings.TrimSuffix(cfg.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &S3Store{api: client, bucket: cfg.Bucket, prefix: prefix, maxSize: maxSize, allowed: allowed}, nil
}

// NewS3Client builds a real AWS SDK v2 client from cfg using a static
// credentials provider and an optional custom endpoint resolver.
func NewS3Client(cfg S3Config) (s3API, error) {
	opts := []func(*s3.Options){
		func(o *s3.Options) {
			o.Credentials = credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")
			o.Region = cfg.Region
		},
	}
	if cfg.Endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.PathStyle
		})
	}
	return s3.New(s3.Options{}, opts...), nil
}

// objectKey returns the S3 object key for a storage key.
func (s *S3Store) objectKey(key string) string {
	return s.prefix + key
}

// Upload stores a file on S3. It returns the attachment ID and storage key,
// mirroring LocalStore semantics (same key format).
func (s *S3Store) Upload(ctx context.Context, filename string, data []byte, orgID, taskID string) (string, string, error) {
	if int64(len(data)) > s.maxSize {
		return "", "", fmt.Errorf("storage: file too large (%d bytes, max %d)", len(data), s.maxSize)
	}
	mimeType := ContentType(filename)
	if !s.allowed[mimeType] {
		return "", "", fmt.Errorf("storage: content type %q not allowed", mimeType)
	}

	// Sanitise SVG (mirror LocalStore; images are re-encoded by the caller).
	if mimeType == "image/svg+xml" {
		var err error
		data, err = sanitiseSVG(data)
		if err != nil {
			return "", "", fmt.Errorf("storage: sanitise svg: %w", err)
		}
	}

	id := ID()
	saneName := sanitizeFilename(filename)
	storageKey := fmt.Sprintf("%s/%s/%s_%s", orgID, taskID, id, saneName)

	_, err := s.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.objectKey(storageKey)),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(mimeType),
	})
	if err != nil {
		return "", "", fmt.Errorf("storage: s3 put: %w", err)
	}
	return id, storageKey, nil
}

// Delete removes a stored object. Missing objects are a no-op.
func (s *S3Store) Delete(ctx context.Context, storageKey string) error {
	_, err := s.api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(storageKey)),
	})
	if err != nil {
		return fmt.Errorf("storage: s3 delete: %w", err)
	}
	return nil
}

// Open returns a reader for a stored object.
func (s *S3Store) Open(ctx context.Context, storageKey string) (io.ReadCloser, error) {
	out, err := s.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(storageKey)),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: s3 get: %w", err)
	}
	return out.Body, nil
}

// putKey writes data at an explicit storage key (used by the migrate helper to
// preserve keys during local→S3 migration).
func (s *S3Store) putKey(ctx context.Context, storageKey string, data []byte, mimeType string) error {
	_, err := s.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.objectKey(storageKey)),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(mimeType),
	})
	if err != nil {
		return fmt.Errorf("storage: s3 putKey: %w", err)
	}
	return nil
}

// Checksum computes the SHA-256 of the object at storageKey (used by the
// migrate helper to verify a copy).
func (s *S3Store) Checksum(ctx context.Context, storageKey string) (string, error) {
	out, err := s.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(storageKey)),
	})
	if err != nil {
		return "", fmt.Errorf("storage: s3 get for checksum: %w", err)
	}
	defer out.Body.Close()
	h := sha256.New()
	if _, err := io.Copy(h, out.Body); err != nil {
		return "", fmt.Errorf("storage: s3 checksum read: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---- S3Config round-trip helpers ----

// S3ConfigJSON encodes cfg as JSON (used by org.storage.configure and the
// org settings UI).
func S3ConfigJSON(cfg S3Config) ([]byte, error) {
	return json.Marshal(cfg)
}

// ParseS3Config decodes a JSON blob into S3Config.
func ParseS3Config(data []byte) (S3Config, error) {
	var cfg S3Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("storage: parse s3 config: %w", err)
	}
	return cfg, nil
}
