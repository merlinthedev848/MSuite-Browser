# MSuite-Browser: Debian 13 Virtual Browser

A secure, high-performance Remote Browser Isolation (RBI) tool built with Node.js, Playwright, and WebSockets.

> **Security Note:** Designed for single-tenant use behind HTTPS. Client sessions run inside per-connection isolated `BrowserContext` instances. Never expose an unauthenticated or default-password instance to the public internet.

---

## Architecture & Features (v2.0 Enterprise)

- **Hardware-Accelerated Canvas Engine:** Replaces laggy DOM image swapping with a high-throughput, desynchronized HTML5 `<canvas>` rendering pipeline driven by off-thread `createImageBitmap()` decoding. Delivers ultra-low latency, 60 FPS streaming, and zero garbage-collection stutter.
- **Remote DevTools Suite:** Inspect remote web applications live! Full remote console stream (`console.log`, `info`, `warn`, `error`) and real-time network monitor capturing HTTP methods, status codes, request URLs, and response MIME types over WebSockets.
- **Real-Time Performance HUD:** On-screen telemetry gauge displaying real-time FPS, round-trip frame latency in milliseconds, active viewport resolution, and dropped frames counter.
- **Dynamic Device Emulation:** Switch viewports instantly without restarting sessions:
  - Desktop 1080p (`1920x1080`)
  - Laptop (`1366x768`)
  - iPad Pro (`1024x1366`)
  - iPhone 15 Pro (`393x852`)
  - Samsung Galaxy S24 (`412x915`)
  - Dynamic Auto-Fit (Matches local browser window)
- **Native Document Export & Full-Page Capture:** Capture crisp viewport screenshots, full-page stitched screenshots, or generate high-fidelity vector PDF documents via native Chromium rendering.
- **Omnibox 2.0 & Multi-Engine Search:** Switch your active search engine directly inside the omnibox (Google, DuckDuckGo, Brave, Bing, Ecosia) with automatic search query expansion and clickable SSL/Isolation status inspector.
- **Session Cookies Inspector & Wipe:** View all cookies stored in the isolated session, complete with domain, security flags (Secure, HttpOnly, SameSite), and one-click cookie deletion.
- **Power Tab Management:** Full tab context menu with duplicate tab, reload tab, close other tabs, and real-time audio playback detection with live mute/unmute toggles.
- **Cross-Site WebSocket Hijacking (CSWSH) Defense:** Strict origin and host validation on WebSocket upgrade and API authentication.
- **SSRF & Private Network Mitigation:** Enforces strict boundary checks blocking internal addresses, loopbacks, link-local addresses, and cloud provider metadata endpoints (`ALLOW_PRIVATE_NAV=0`).
- **Interactive JavaScript Dialogs:** Captures and presents remote `alert()`, `confirm()`, and `prompt()` modals without freezing browser execution.
- **Ad & Tracker Defense:** Built-in ad and tracker blocking powered by `@ghostery/adblocker-playwright`.
- **Integrated SOCKS5 / WARP Routing:** Optional userspace Cloudflare WARP client or custom SOCKS5/HTTP proxy support.
- **Anti-Automation Detection:** Strips automation flags (`--disable-blink-features=AutomationControlled`, removes `navigator.webdriver`) to bypass anti-bot and Cloudflare checks.
- **Synchronized Clipboard & File Handling:** Instantaneous text insertion (`insertText`) and sanitized multi-file uploads and downloads.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + T` | Open new tab |
| `Ctrl + W` | Close current tab |
| `Ctrl + R` | Reload current tab |
| `Ctrl + L` | Focus Omnibox URL bar |
| `Ctrl + Shift + I` | Toggle Remote DevTools Drawer (Console/Network) |
| `Ctrl + Shift + H` | Toggle Browsing History Drawer |
| `Escape` | Dismiss any open modal, drawer, or dropdown menu |

---

## Quick Install (Debian 13 / Debian 12 / Ubuntu)

### Automated Install

Clone the repository and run the installer:

```bash
git clone https://github.com/merlinthedev848/MSuite-Browser.git msuite-browser
cd msuite-browser
chmod +x install.sh
./install.sh
```

Or execute the setup script directly:

```bash
curl -fsSL https://raw.githubusercontent.com/merlinthedev848/MSuite-Browser/main/install.sh -o install.sh
chmod +x install.sh && ./install.sh
```

The installer verifies prerequisites, prompts for a strong session password (min 8 characters), builds the Docker container, and launches the service.

---

## Manual Docker Deployment

```bash
git clone https://github.com/merlinthedev848/MSuite-Browser.git
cd MSuite-Browser
mkdir -p browser_data/downloads && chmod 700 browser_data

# Build image
docker build -t msuite-browser .

# Run container
docker run -d \
  -p 3000:3000 \
  -e PASSWORD="your_strong_password_here" \
  -e TRUST_PROXY=0 \
  -v "$(pwd)/browser_data:/usr/src/app/browser_data" \
  --shm-size 2g \
  --name msuite-browser \
  --restart unless-stopped \
  msuite-browser
```

---

## Configuration & Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PASSWORD` | _(required)_ | Authentication password (minimum 8 characters, not `password123`) |
| `TRUST_PROXY` | `0` | Set to `1` when running behind a trusted reverse proxy (Nginx, Caddy, Traefik) |
| `ALLOW_PRIVATE_NAV` | `0` | Set to `1` to allow navigation and subresources to RFC1918 / localhost addresses |
| `MAX_TABS` | `8` | Maximum concurrent tabs per session |
| `MAX_WS_SESSIONS` | `6` | Maximum concurrent WebSocket client sessions |
| `MAX_UPLOAD_BYTES` | `8388608` | Maximum file upload size in bytes (8 MB) |
| `IDLE_TTL_MS` | `7200000` | Idle session expiry (2 hours) |
| `TOKEN_TTL_MS` | `43200000` | Absolute token lifetime (12 hours) |
| `ENABLE_WARP` | `1` | Enable/disable Cloudflare WARP userspace SOCKS5 daemon (`amd64`) |
| `ABUSEIPDB_KEY` | `null` | Optional AbuseIPDB API key for automatic threat blocking and reporting |

---

## Production Reverse Proxy Setup

Always terminate TLS at your reverse proxy and forward WebSocket upgrade headers. Set `TRUST_PROXY=1` in your container environment.

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name browser.example.com;

    ssl_certificate     /etc/ssl/certs/browser.crt;
    ssl_certificate_key /etc/ssl/private/browser.key;

    client_max_body_size 16M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

### Caddy Configuration

```caddy
browser.example.com {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
        header_up X-Forwarded-Host {host}
    }
}
```

---

## Health Checks & Persistence

- **Health Check Endpoint:** `GET /healthz` (returns `200 OK` when browser engine is operational; `503 Service Unavailable` during startup or engine recovery).
- **Session Persistence:** Hashed authentication tokens persist in `browser_data/sessions.json`.
- **Downloads Directory:** Downloaded files are stored with unique, collision-proof identifiers under `browser_data/downloads` and automatically purged after 24 hours.
