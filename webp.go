package webptransform

import (
    "bytes"
    "golang.org/x/crypto/blake2b"
    "encoding/hex"
    "fmt"
    "image"
    "image/jpeg"
    "image/png"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
    "github.com/kolesa-team/go-webp/webp"
    "github.com/kolesa-team/go-webp/encoder"
)

func init() {
    caddy.RegisterModule(WebPTransform{})
}

type WebPTransform struct {
    Cache string `json:"cache"`
    mu    sync.Mutex
}

func (WebPTransform) CaddyModule() caddy.ModuleInfo {
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
    return nil
}

func (m *WebPTransform) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    if !strings.Contains(r.Header.Get("Accept"), "image/webp") {
        return next.ServeHTTP(w, r)
    }

    // Intercept response
    rw := &interceptResponseWriter{
        ResponseWriter: w,
        header:         make(http.Header),
        buf:            &bytes.Buffer{},
    }

    err := next.ServeHTTP(rw, r)
    if err != nil {
        return err
    }

    contentType := rw.header.Get("Content-Type")
    if !(strings.HasPrefix(contentType, "image/png") || strings.HasPrefix(contentType, "image/jpeg")) {
        rw.WriteToOriginal(w)
        return nil
    }

    hashedName := hashPath(r.URL.Path)
    cachePath := filepath.Join(m.Cache, hashedName+".webp")

    if _, err := os.Stat(cachePath); err == nil {
        w.Header().Set("Content-Type", "image/webp")
        http.ServeFile(w, r, cachePath)
        return nil
    }

    var img image.Image
    var decodeErr error
    if strings.HasPrefix(contentType, "image/png") {
        img, decodeErr = png.Decode(bytes.NewReader(rw.buf.Bytes()))
    } else {
        img, decodeErr = jpeg.Decode(bytes.NewReader(rw.buf.Bytes()))
    }

    if decodeErr != nil {
        rw.WriteToOriginal(w)
        return nil
    }

    options, err := encoder.NewLossyEncoderOptions(encoder.PresetDefault, 75)
    if err != nil {
        rw.WriteToOriginal(w)
        return nil
    }

    var buf bytes.Buffer

    if err := webp.Encode(&buf, img, options); err != nil {
        rw.WriteToOriginal(w)
        return nil
    }

    m.mu.Lock()
    _ = os.MkdirAll(filepath.Dir(cachePath), 0755)
    _ = os.WriteFile(cachePath, buf.Bytes(), 0644)
    m.mu.Unlock()

    w.Header().Set("Content-Type", "image/webp")
    w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
    _, _ = w.Write(buf.Bytes())
    return nil
}

func hashPath(path string) string {
    h, _ := blake2b.New256(nil)
    h.Write([]byte(path))
    return hex.EncodeToString(h.Sum(nil))
}

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
)
