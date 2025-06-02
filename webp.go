package webpoptimizer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/kolesa-team/go-webp/encoder"
	"github.com/kolesa-team/go-webp/webp"
)

// The default quality for webp encoding
const defaultQuality = 75

// The default maximum cache size in bytes, 0 means no limit
const defaultMaxCacheSize = 0

type WebPOptimizer struct {
	Cache        string  `json:"cache"`                    // Directory to cache webp images
	Quality      float32 `json:"quality,omitempty"`        // Quality for webp encoding, 0-100, default is 75
	MaxCacheSize int64   `json:"max_cache_size,omitempty"` // Maximum size of the cache in bytes, 0 means no limit

	CurrentCacheSize int64 // Current size of the cache in bytes, used for monitoring
	mu               sync.Mutex
}

func hashData(data []byte) string {
	// Hashes the given data using blake3
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func init() {
	caddy.RegisterModule(&WebPOptimizer{})
	httpcaddyfile.RegisterHandlerDirective("webp_optimizer", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(WebPOptimizer)
	m.Cache = filepath.Join(os.TempDir(), "webp_optimizer")
	m.Quality = defaultQuality
	m.MaxCacheSize = defaultMaxCacheSize
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (m *WebPOptimizer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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

				m.Quality = float32(q)
			case "max_cache_size":
				if !d.NextArg() {
					return d.ArgErr()
				}

				sizeStr := d.Val()
				size, err := strconv.ParseInt(sizeStr, 10, 64)

				if err != nil {
					return d.Errf("invalid max_cache_size value: %v", err)
				}

				m.MaxCacheSize = size
			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}

	return nil
}

func (*WebPOptimizer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.webp_optimizer",
		New: func() caddy.Module { return new(WebPOptimizer) },
	}
}

func (m *WebPOptimizer) Provision(ctx caddy.Context) error {
	// Ensure the cache directory exists, create it if not
	if err := os.MkdirAll(m.Cache, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %v", err)
	}

	// Calculate the current cache size
	var totalSize int64

	err := filepath.Walk(m.Cache, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to calculate cache size: %v", err)
	}

	m.CurrentCacheSize = totalSize
	return nil
}

func (m *WebPOptimizer) Validate() error {
	if m.Cache == "" {
		return fmt.Errorf("cache directory must be set")
	}

	if m.Quality < 0 || m.Quality > 100 {
		return fmt.Errorf("quality must be between 0 and 100, got %d", m.Quality)
	}

	if m.MaxCacheSize < 0 {
		return fmt.Errorf("max_cache_size must be a non-negative integer, got %d", m.MaxCacheSize)
	}

	return nil
}

func (m *WebPOptimizer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
	data := rw.buf.Bytes()
	hashedName := hashData(data)
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
		img, decodeErr = png.Decode(bytes.NewReader(data))
	} else {
		img, decodeErr = jpeg.Decode(bytes.NewReader(data))
	}

	if decodeErr != nil {
		// We couldn't decode it, so we just pass through the original response
		rw.WriteToOriginal(w)
		return nil
	}

	// Now, let's encode the image to webp format
	options, err := encoder.NewLossyEncoderOptions(encoder.PresetDefault, m.Quality)

	if err != nil {
		log.Fatalln(err)
	}

	var buf bytes.Buffer

	if err := webp.Encode(&buf, img, options); err != nil {
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
		newFileSize := int64(buf.Len())

		// Check if adding this file would exceed the cache size limit (if set)
		for m.MaxCacheSize > 0 && newFileSize < m.MaxCacheSize && m.CurrentCacheSize+newFileSize > m.MaxCacheSize {
			// Remove the largest file in the cache
			var largestPath string
			var largestSize int64

			_ = filepath.Walk(m.Cache, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				if info.Size() > largestSize {
					largestSize = info.Size()
					largestPath = path
				}
				return nil
			})

			if largestPath == "" {
				break // Nothing to remove
			}

			if err := os.Remove(largestPath); err == nil {
				// The file has been removed, upate the current cache size
				m.CurrentCacheSize -= largestSize
			}
		}

		// We managed to save some data, so we write the webp image to the cache
		if writeErr := os.WriteFile(cachePath, buf.Bytes(), 0644); writeErr != nil {
			caddy.Log().Error("failed to write webp cache file", zap.String("path", cachePath), zap.Error(writeErr))
		} else {
			m.CurrentCacheSize += newFileSize
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
	_ caddy.Module                = (*WebPOptimizer)(nil)
	_ caddyhttp.MiddlewareHandler = (*WebPOptimizer)(nil)
	_ caddyfile.Unmarshaler       = (*WebPOptimizer)(nil)
)
