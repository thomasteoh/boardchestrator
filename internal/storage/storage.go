// Package storage defines the attachment storage interface and provides
// a local-filesystem backend. See SPEC §9.
package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ID generates a random 16-byte hex identifier (same scheme as action.newID).
func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Store is the attachment storage interface.
type Store interface {
	// Upload stores a file and returns the attachment ID, storage key, and the
	// MIME type derived from the filename extension (never the caller-supplied
	// type — see WU-519). The returned mime is what the server will serve, so
	// callers must store it and discard any client-claimed type.
	Upload(ctx context.Context, filename string, data []byte, orgID, taskID string) (attachmentID, storageKey, mime string, err error)
	// Delete removes a stored file by its storage key.
	Delete(ctx context.Context, storageKey string) error
	// Open returns a reader for a stored file by storage key.
	Open(ctx context.Context, storageKey string) (io.ReadCloser, error)
}

// Config for the local backend.
type Config struct {
	DataDir      string   // root data directory (BC_DATA_DIR)
	MaxSize      int64    // per-file size limit (default 10MB)
	ContentTypes []string // allowed MIME types (default: common document/image types)
}

// LocalStore implements Store on the local filesystem.
type LocalStore struct {
	base    string
	maxSize int64
	allowed map[string]bool
}

// NewLocalStore creates a LocalStore with the given config.
func NewLocalStore(cfg Config) *LocalStore {
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 10 << 20 // 10MB
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/data"
	}
	allowed := make(map[string]bool)
	for _, t := range cfg.ContentTypes {
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
	return &LocalStore{base: cfg.DataDir, maxSize: cfg.MaxSize, allowed: allowed}
}

// storagePath returns the absolute file path for a storage key.
func (s *LocalStore) storagePath(key string) string {
	// key format: <org>/<task>/<id>_<sanitized-filename>
	// Ensure path is under base to prevent traversal.
	clean := filepath.Clean(filepath.Join(s.base, "attachments", key))
	if !strings.HasPrefix(clean, s.base) {
		clean = filepath.Join(s.base, "attachments", "invalid")
	}
	return clean
}

// sanitizeFilename strips path separators and special chars.
func sanitizeFilename(name string) string {
	// Keep alphanumeric, dash, underscore, dot
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := b.String()
	if len(s) > 255 {
		s = s[:255]
	}
	return s
}

// Upload stores a file on the local filesystem. The returned MIME is derived
// from the filename extension and is the type the server will serve (WU-519).
func (s *LocalStore) Upload(ctx context.Context, filename string, data []byte, orgID, taskID string) (string, string, string, error) {
	// Validate size
	if int64(len(data)) > s.maxSize {
		return "", "", "", fmt.Errorf("storage: file too large (%d bytes, max %d)", len(data), s.maxSize)
	}

	// Validate content type from filename extension
	ext := strings.ToLower(filepath.Ext(filename))
	// Map common extensions to MIME types for validation
	extMIME := map[string]string{
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".gif":  "image/gif",
		".webp": "image/webp",
		".pdf":  "application/pdf",
		".txt":  "text/plain",
		".csv":  "text/csv",
		".json": "application/json",
		".svg":  "image/svg+xml",
	}
	mimeType, ok := extMIME[ext]
	if !ok {
		mimeType = "application/octet-stream"
	}
	if !s.allowed[mimeType] {
		return "", "", "", fmt.Errorf("storage: content type %q not allowed", mimeType)
	}

	// Re-encode images to strip metadata
	if mimeType == "image/png" || mimeType == "image/jpeg" {
		img, _, err := image.Decode(bytes.NewReader(data))
		if err == nil {
			var buf bytes.Buffer
			if mimeType == "image/png" {
				if err := png.Encode(&buf, img); err != nil {
					return "", "", "", fmt.Errorf("storage: re-encode png: %w", err)
				}
			} else {
				if err := jpeg.Encode(&buf, img, nil); err != nil {
					return "", "", "", fmt.Errorf("storage: re-encode jpeg: %w", err)
				}
			}
			data = buf.Bytes()
		}
	}

	// Sanitise SVG
	if mimeType == "image/svg+xml" {
		var err error
		data, err = sanitiseSVG(data)
		if err != nil {
			return "", "", "", fmt.Errorf("storage: sanitise svg: %w", err)
		}
	}

	id := ID()
	saneName := sanitizeFilename(filename)
	storageKey := fmt.Sprintf("%s/%s/%s_%s", orgID, taskID, id, saneName)

	path := s.storagePath(storageKey)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", "", fmt.Errorf("storage: mkdir: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", "", "", fmt.Errorf("storage: write: %w", err)
	}

	return id, storageKey, mimeType, nil
}

// Delete removes a stored file.
func (s *LocalStore) Delete(ctx context.Context, storageKey string) error {
	path := s.storagePath(storageKey)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("storage: delete: %w", err)
	}
	return nil
}

// Open returns a reader for a stored file.
func (s *LocalStore) Open(ctx context.Context, storageKey string) (io.ReadCloser, error) {
	path := s.storagePath(storageKey)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	return f, nil
}

// --- SVG sanitisation ---

// SVGElement represents a parsed SVG element for sanitisation.
type SVGElement struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any"`
	Content []byte     `xml:",innerxml"`
}

func sanitiseSVG(data []byte) ([]byte, error) {
	// Simple approach: strip event attributes and dangerous elements
	// by scanning the raw XML for known dangerous patterns.
	// This is not a full XML parser — we use a simple regex-free approach
	// that removes <script>, <foreignObject>, on* attributes.

	// Remove script tags and their content
	cleaned := removeTags(data, "script")
	cleaned = removeTags(cleaned, "foreignObject")

	// Strip event handler attributes (onclick, onload, etc.)
	cleaned = stripEventAttrs(cleaned)

	return cleaned, nil
}

func removeTags(data []byte, tag string) []byte {
	open := []byte("<" + tag + " ")
	close := []byte("</" + tag + ">")
	selfClose := []byte("/>")

	var out bytes.Buffer
	i := 0
	for i < len(data) {
		// Check for opening tag
		if bytes.HasPrefix(data[i:], open) || bytes.HasPrefix(data[i:], []byte("<"+tag+">")) {
			// Find closing tag
			j := i + 1
			depth := 1
			for j < len(data) && depth > 0 {
				if bytes.HasPrefix(data[j:], open) || bytes.HasPrefix(data[j:], []byte("<"+tag+">")) {
					depth++
					j++
				} else if bytes.HasPrefix(data[j:], close) || bytes.HasPrefix(data[j:], []byte("</"+tag+">")) {
					depth--
					j++
				} else {
					j++
				}
			}
			i = j
			continue
		}
		// Check for self-closing tag
		if bytes.HasPrefix(data[i:], []byte("<"+tag+" ")) {
			si := bytes.Index(data[i:], selfClose)
			if si >= 0 {
				i += si + 2
				continue
			}
		}
		out.WriteByte(data[i])
		i++
	}
	return out.Bytes()
}

func stripEventAttrs(data []byte) []byte {
	// Strip on* attributes: on\w+\s*=\s*"[^"]*" or on\w+\s*=\s*'[^']*'
	var out bytes.Buffer
	i := 0
	for i < len(data) {
		// Look for pattern "on" followed by word chars then "="
		if i+2 < len(data) && data[i] == ' ' && data[i+1] == 'o' && data[i+2] == 'n' {
			// Check if this is an attribute
			j := i + 3
			for j < len(data) && (data[j] == '_' || (data[j] >= 'a' && data[j] <= 'z') || (data[j] >= 'A' && data[j] <= 'Z')) {
				j++
			}
			if j < len(data) && data[j] == '=' {
				// This is an event handler — skip the whole attribute
				i = j + 1
				// Skip quotes and value
				if i < len(data) && (data[i] == '"' || data[i] == '\'') {
					quote := data[i]
					i++
					for i < len(data) && data[i] != quote {
						i++
					}
					if i < len(data) {
						i++ // skip closing quote
					}
				}
				continue
			}
		}
		out.WriteByte(data[i])
		i++
	}
	return out.Bytes()
}

// --- Multipart parsing helpers ---

// ReadUpload parses a multipart form upload and returns the filename and data.
func ReadUpload(r *http.Request, maxSize int64) (filename string, data []byte, err error) {
	if err := r.ParseMultipartForm(maxSize); err != nil {
		return "", nil, fmt.Errorf("storage: parse multipart: %w", err)
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		return "", nil, fmt.Errorf("storage: no file in upload: %w", err)
	}
	defer f.Close()

	data, err = io.ReadAll(io.LimitReader(f, maxSize))
	if err != nil {
		return "", nil, fmt.Errorf("storage: read upload: %w", err)
	}
	return h.Filename, data, nil
}

// ContentType returns the MIME type for a filename.
func ContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	m := mime.TypeByExtension(ext)
	if m != "" {
		// Strip any parameters
		if i := strings.IndexByte(m, ';'); i >= 0 {
			m = m[:i]
		}
		return m
	}
	return "application/octet-stream"
}
