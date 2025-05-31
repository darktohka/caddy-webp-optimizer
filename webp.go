package webptransform

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/crypto/blake2b"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gen2brain/webp"
)

// The default quality for webp encoding
const defaultQuality = 75

// The default effort level for webp encoding
const defaultEffort = 4

type WebPTransform struct {
	Cache   string `json:"cache"`             // Directory to cache webp images
	Quality int    `json:"quality,omitempty"` // Quality for webp encoding, 0-100, default is 75
	Effort  int    `json:"effort,omitempty"`  // Effort level for webp encoding, 0-6, default is 4
	mu      sync.Mutex
}

func hashPath(path string) string {
	// Hashes the given path using blake2b
	h, _ := blake2b.New256(nil)
	h.Write([]byte(path))
	return hex.EncodeToString(h.Sum(nil))
}

func init() {
	caddy.RegisterModule(&WebPTransform{})
	httpcaddyfile.RegisterHandlerDirective("webp_transform", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(WebPTransform)
	m.Cache = filepath.Join(os.TempDir(), "webp_transform")
	m.Quality = defaultQuality
	m.Effort = defaultEffort
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (m *WebPTransform) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "cache":
				if !d.NextArg() {
					return d.ArgErr()
				}

				m.Cache = d.Val()
			case "quality":
				if !d.NextArg() {
					return d.ArgErr()
				}

				q, err := strconv.Atoi(d.Val())

				if err != nil {
					return d.Errf("invalid quality value: %v", err)
				}

				m.Quality = q
			case "effort":
				if !d.NextArg() {
					return d.ArgErr()
				}

				q, err := strconv.Atoi(d.Val())

				if err != nil {
					return d.Errf("invalid effort value: %v", err)
				}

				m.Effort = q
			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}

	return nil
}

func (*WebPTransform) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.webp_transform",
		New: func() caddy.Module { return new(WebPTransform) },
	}
}

func (m *WebPTransform) Provision(ctx caddy.Context) error {
	return nil
}

func (m *WebPTransform) Validate() error {
	if m.Cache == "" {
		return fmt.Errorf("cache directory must be set")
	}

	if m.Quality < 0 || m.Quality > 100 {
		return fmt.Errorf("quality must be between 0 and 100, got %d", m.Quality)
	}

	if m.Effort < 0 || m.Effort > 6 {
		return fmt.Errorf("effort must be between 0 and 6, got %d", m.Effort)
	}

	// Ensure the cache directory exists, create it if not
	if err := os.MkdirAll(m.Cache, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %v", err)
	}

	return nil
}

func (m *WebPTransform) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// If the request does not accept webp, skip the transformation
	if !strings.Contains(r.Header.Get("Accept"), "image/webp") {
		return next.ServeHTTP(w, r)
	}

	// We accept webp, let's see if we receive an image
	rw := &interceptResponseWriter{
		ResponseWriter: w,
		header:         make(http.Header),
		buf:            &bytes.Buffer{},
	}

	// Run the next handler and capture the response
	// This will call all the middlewares in the chain
	// The output can be an image or any other content
	err := next.ServeHTTP(rw, r)

	if err != nil {
		return err
	}

	// Let's check if the response is a supported image
	contentType := rw.header.Get("Content-Type")

	if !(strings.HasPrefix(contentType, "image/png") || strings.HasPrefix(contentType, "image/jpeg")) {
		// This isn't an image we can transform, so we just pass it through
		rw.WriteToOriginal(w)
		return nil
	}

	// This is an image we can transform! First, let's see if we have it cached
	hashedName := hashPath(r.URL.Path)
	cachePath := filepath.Join(m.Cache, hashedName+".webp")

	if stat, err := os.Stat(cachePath); err == nil {
		if stat.Size() > 0 {
			// We have a cached version, let's serve it
			http.ServeFile(w, r, cachePath)
		} else {
			// The cached file exists but is empty, this means the original response should be used
			rw.WriteToOriginal(w)
		}

		return nil
	}

	// Not cached! Let's decode the image first
	var img image.Image
	var decodeErr error

	if strings.HasPrefix(contentType, "image/png") {
		img, decodeErr = png.Decode(bytes.NewReader(rw.buf.Bytes()))
	} else {
		img, decodeErr = jpeg.Decode(bytes.NewReader(rw.buf.Bytes()))
	}

	if decodeErr != nil {
		// We couldn't decode it, so we just pass through the original response
		rw.WriteToOriginal(w)
		return nil
	}

	// Now, let's encode the image to webp format
	var buf bytes.Buffer

	if err := webp.Encode(&buf, img, webp.Options{Quality: m.Quality, Lossless: false, Method: m.Effort, Exact: false}); err != nil {
		// Pass through original response
		rw.WriteToOriginal(w)
		return nil
	}

	// Write the encoded image to the cache
	m.mu.Lock()
	defer m.mu.Unlock()

	if buf.Len() >= rw.buf.Len() {
		// We couldn't save any data by encoding to webp, so we just pass through the original response
		// We write an empty file to the cache to avoid re-encoding the same image
		if writeErr := os.WriteFile(cachePath, []byte{}, 0644); writeErr != nil {
			caddy.Log().Error("failed to write webp cache file", zap.String("path", cachePath), zap.Error(writeErr))
		}

		rw.WriteToOriginal(w)
		return nil
	} else {
		// We managed to save some data, so we write the webp image to the cache
		if writeErr := os.WriteFile(cachePath, buf.Bytes(), 0644); writeErr != nil {
			caddy.Log().Error("failed to write webp cache file", zap.String("path", cachePath), zap.Error(writeErr))
		}
	}

	// Add the original headers to the response
	for k, vv := range rw.Header() {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Add the webp specific headers
	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

	// Write the image data to the response
	if _, err = w.Write(buf.Bytes()); err != nil {
		caddy.Log().Error("failed to write webp response", zap.Error(err))
	}

	return nil
}

// The interceptor is responsible for capturing the response
// so we can modify it before sending it to the client.
type interceptResponseWriter struct {
	http.ResponseWriter
	header http.Header
	buf    *bytes.Buffer
	status int
}

func (rw *interceptResponseWriter) Header() http.Header {
	return rw.header
}

func (rw *interceptResponseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
}

func (rw *interceptResponseWriter) Write(b []byte) (int, error) {
	return rw.buf.Write(b)
}

func (rw *interceptResponseWriter) WriteToOriginal(w http.ResponseWriter) {
	for k, vv := range rw.header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	if rw.status != 0 {
		w.WriteHeader(rw.status)
	}

	_, _ = io.Copy(w, rw.buf)
}

// Interface guards
var (
	_ caddy.Module                = (*WebPTransform)(nil)
	_ caddyhttp.MiddlewareHandler = (*WebPTransform)(nil)
	_ caddyfile.Unmarshaler       = (*WebPTransform)(nil)
)
