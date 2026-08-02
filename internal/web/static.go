// Package web holds the browser-facing handlers, templ views, and embedded
// static assets for the app shell.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed static
var staticFS embed.FS

// hashLen is the number of hex characters of the SHA-256 content hash
// embedded in cache-busted asset URLs.
const hashLen = 12

// assetSet maps logical asset names (paths relative to static/, e.g.
// "app.css" or "vendor/htmx.min.js") to their content-hashed forms and back.
type assetSet struct {
	// urls: logical name -> URL path ("/static/app.<hash>.css").
	urls map[string]string
	// logical: hashed relative path ("app.<hash>.css") -> logical name.
	logical map[string]string
}

var assets = mustBuildAssets()

func mustBuildAssets() *assetSet {
	a := &assetSet{
		urls:    map[string]string{},
		logical: map[string]string{},
	}
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := staticFS.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read embedded asset %s: %w", p, err)
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])[:hashLen]
		rel := strings.TrimPrefix(p, "static/")
		hashed := hashedName(rel, hash)
		a.urls[rel] = "/static/" + hashed
		a.logical[hashed] = rel
		return nil
	})
	if err != nil {
		// Embedded FS is fixed at compile time, so this is a build defect;
		// failing at package init (startup) is correct, not a request-path panic.
		panic(fmt.Sprintf("web: building static asset table: %v", err))
	}
	return a
}

// hashedName inserts the content hash before the final extension:
// "app.css" -> "app.<hash>.css", "vendor/htmx.min.js" -> "vendor/htmx.min.<hash>.js".
func hashedName(rel, hash string) string {
	dir, base := path.Split(rel)
	if i := strings.LastIndex(base, "."); i >= 0 {
		return dir + base[:i] + "." + hash + base[i:]
	}
	return dir + base + "." + hash
}

// AssetURL returns the cache-busted URL path for a logical asset name
// relative to static/ (e.g. AssetURL("app.css") -> "/static/app.abc123def456.css").
// Unknown names fall back to the unhashed path, which the handler serves
// with no-cache, so a typo degrades caching rather than the page.
func AssetURL(name string) string {
	if u, ok := assets.urls[name]; ok {
		return u
	}
	return "/static/" + name
}

// StaticHandler serves the embedded static tree under /static/.
// Content-hashed URLs get immutable far-future caching; plain paths are
// served no-cache. Anything else is 404.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("web: static subtree: %v", err)) // compile-time layout defect
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rel := strings.TrimPrefix(r.URL.Path, "/static/")
		// Reject anything not in canonical form (dot-dot, doubled slashes,
		// absolute); the embed FS cannot escape the tree, but a clean 404
		// beats surprising lookups.
		if rel == "" || rel != path.Clean(rel) || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("X-Content-Type-Options", "nosniff")

		if logical, ok := assets.logical[rel]; ok {
			// Content-addressed: safe to cache forever.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			serveAsset(w, r, sub, logical)
			return
		}
		if _, ok := assets.urls[rel]; ok {
			// Unhashed direct fetch: always revalidate.
			w.Header().Set("Cache-Control", "no-cache")
			serveAsset(w, r, sub, rel)
			return
		}
		http.NotFound(w, r)
	})
}

func serveAsset(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	// Serve under the asset's own name so ServeFileFS derives the correct
	// Content-Type from the real extension regardless of the requested URL.
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/" + name
	http.ServeFileFS(w, r2, fsys, name)
}
