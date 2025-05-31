WebP Optimizer Module for Caddy
===============================

This package provides a WebP image optimization module for [Caddy](https://github.com/caddyserver/caddy). It serves images in the WebP format through on-the-fly conversion for improved performance and reduced bandwidth.

## Caddy module name

```
http.handlers.webp_optimizer
```

## Features

- Converts supported image formats (JPEG and PNG) to WebP on the fly
- Caches optimized images for faster subsequent requests
- Configurable quality and cache settings
- Seamless integration with Caddy's HTTP pipeline
- Automatically falls back to original images for clients that do not support WebP
- Automatically falls back to the original image if converted image is less efficient than the original
- Handles cache size limits to prevent excessive disk usage

## Configuration

You can configure the WebP optimizer in your Caddyfile or via Caddy's JSON config.

### Caddyfile Example

```Caddyfile
route {
    webp_optimizer {
        # Optional: set quality (default: 75)
        quality 75

        # Optional: cache directory (default: /tmp/webp_transform)
        cache /tmp/webp_transform

        # Optional: maximum cache size in bytes (default: no limit)
        max_cache_size 1073741824 # 1 GB
    }

    file_server
}
```

### JSON Example

```json
{
    "handler": "webp_optimizer",
    "quality": 75,
    "cache": "/tmp/webp_transform",
    "max_cache_size": 1073741824
}
```

## Usage

- Place the `webp_optimizer` handler before your `file_server` directive.
- Requests for supported image types will be served as WebP if the client supports it.
- Non-WebP-capable clients will receive the original image.

### WebP not served

- Verify the client (browser) sends `Accept: image/webp` in the request headers.
- Verify that the `webp_optimizer` handler is set before the handler that serves your original image in your Caddyfile or JSON config.
