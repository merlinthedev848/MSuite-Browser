# Virtual Browser (BrowserBox Alternative)

A secure, performant Remote Browser Isolation (RBI) tool built with Node.js and Playwright.

> **Security note:** Designed for **single-tenant** use behind HTTPS. All clients share one Chromium process with per-connection BrowserContexts. Do not expose an unauthenticated or default-password instance to the internet.

## Features
- **Endpoint isolation:** Page code runs on the remote server, not the operator device.
- **Multi-tab support** with capped tabs per session.
- **Ad & tracker blocking** via Ghostery (Playwright).
- **Cookie-based session auth** (HttpOnly) + idle/absolute token expiry.
- **Authenticated downloads** with sanitized filenames.
- **Optional Cloudflare WARP VPN** (userspace SOCKS5) and custom proxies.
- **Full input passthrough** for mouse, keyboard, and common shortcuts.

## One-Line Quick Install (Debian/Ubuntu)

```bash
curl -sSL https://raw.githubusercontent.com/merlinthedev848/browser/main/install.sh | bash
```

The script **requires** a strong password (no default). Prefer cloning the repo and reviewing `install.sh` before piping to bash when you can.

## Manual Docker Deployment

```bash
git clone https://github.com/merlinthedev848/browser.git
cd browser
mkdir -p browser_data && chmod 700 browser_data
docker build -t virtual-browser .
docker run -d \
  -p 3000:3000 \
  -e PASSWORD="your_strong_password_here" \
  -v "$(pwd)/browser_data:/usr/src/app/browser_data" \
  --shm-size 1g \
  --name vbrowser \
  --restart unless-stopped \
  virtual-browser
```

### Important environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PASSWORD` | _(required)_ | Login password (not `password123`, min 8 chars) |
| `TRUST_PROXY` | `0` | Set `1` behind a trusted reverse proxy |
| `ALLOW_PRIVATE_NAV` | `0` | Set `1` to allow localhost/RFC1918 navigation |
| `MAX_TABS` | `8` | Max tabs per WebSocket session |
| `MAX_WS_SESSIONS` | `6` | Max concurrent browser sessions |
| `IDLE_TTL_MS` | `7200000` | Idle session expiry (2h) |
| `ENABLE_WARP` | `1` | Set `0` to skip WARP in entrypoint |

### Production

Always terminate TLS with Nginx or Caddy, enable WebSocket upgrades, forward `X-Forwarded-Proto`, and set `TRUST_PROXY=1`.

Health check: `GET /healthz`.

### Persistence

Auth sessions (hashed tokens) persist under `browser_data/sessions.json`. **Site cookies are not persisted** across disconnects — each WebSocket gets a fresh BrowserContext by design.
