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

## Install / update (Debian/Ubuntu)

### If the GitHub repo is **private** (current default)

Unauthenticated `wget`/`curl` to `raw.githubusercontent.com` will download `404: Not Found` and the installer cannot run. Use git with credentials instead:

```bash
# First time
git clone https://github.com/merlinthedev848/browser.git virtual-browser
cd virtual-browser
chmod +x install.sh
./install.sh

# Later updates (from inside the clone, or let install.sh reset --hard origin/main)
cd virtual-browser
git fetch origin main && git reset --hard origin/main
./install.sh
```

Or with a Personal Access Token:

```bash
curl -fsSL -H "Authorization: Bearer YOUR_GH_PAT" \
  https://raw.githubusercontent.com/merlinthedev848/browser/main/install.sh \
  -o install.sh
chmod +x install.sh && ./install.sh
```

### If you make the repo **public**

Then the classic one-liner works:

```bash
curl -fsSL https://raw.githubusercontent.com/merlinthedev848/browser/main/install.sh -o install.sh
chmod +x install.sh && ./install.sh
```

(`curl ... | bash` also works once public; prefer saving the script first so a 404 cannot be executed.)

The script **requires** a strong password (8+ chars, not `password123`). Existing `vbrowser` container passwords are reused when present.

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
