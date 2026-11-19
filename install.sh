#!/bin/bash
set -euo pipefail

echo "=========================================================="
echo "  MSuite-Browser: Debian 13 Virtual Browser - Quick Install"
echo "=========================================================="

# Guard: if this file was saved from a GitHub 404 (private/raw URL without auth), abort early.
if ! head -1 "$0" 2>/dev/null | grep -q '^#!/bin/bash'; then
    echo "[!] This install.sh does not look like a valid script."
    echo "    If you used wget/curl against raw.githubusercontent.com and encountered an issue,"
    echo "    clone with git instead:"
    echo "      git clone https://github.com/merlinthedev848/MSuite-Browser.git"
    echo "      cd MSuite-Browser && ./install.sh"
    exit 1
fi

# 1. Install system dependencies (Debian 13 Trixie / Debian 12 Bookworm)
echo "[*] Ensuring required system packages are installed..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y -q
    sudo apt-get install -y git docker.io curl ca-certificates
fi

# Ensure Docker service is enabled and running
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl enable --now docker 2>/dev/null || true
fi

# 2. Clone or update the repository
REPO_URL="https://github.com/merlinthedev848/MSuite-Browser.git"
INSTALL_DIR="MSuite-Browser"

# If already inside a checkout of this repo, update in place
if [ -f "./server.js" ] && [ -f "./Dockerfile" ] && [ -d "./.git" ]; then
    echo "[*] Running from existing checkout — updating working copy..."
    git fetch origin main 2>/dev/null || true
    git reset --hard origin/main 2>/dev/null || true
    INSTALL_DIR="."
fi

if [ "$INSTALL_DIR" != "." ]; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "[*] Existing installation directory found — updating..."
        cd "$INSTALL_DIR"
        git fetch origin main
        git reset --hard origin/main
    else
        echo "[*] Cloning MSuite-Browser repository..."
        if ! git clone "$REPO_URL" "$INSTALL_DIR"; then
            echo "[!] git clone failed. Check repository permissions or network connection."
            exit 1
        fi
        cd "$INSTALL_DIR"
    fi
fi

# 3. Ensure persistent data directory exists with restricted permissions
echo "[*] Configuring persistent storage (browser_data)..."
mkdir -p browser_data/downloads
chmod 700 browser_data

# 4. Password validation (require 8+ chars, forbid insecure defaults)
echo ""
EXISTING_PASSWORD=""
if sudo docker ps -a --format '{{.Names}}' | grep -q "^vbrowser$"; then
    EXISTING_PASSWORD=$(sudo docker inspect --format='{{range .Config.Env}}{{if eq (slice . 0 9) "PASSWORD="}}{{slice . 9}}{{end}}{{end}}' vbrowser 2>/dev/null || true)
elif sudo docker ps -a --format '{{.Names}}' | grep -q "^msuite-browser$"; then
    EXISTING_PASSWORD=$(sudo docker inspect --format='{{range .Config.Env}}{{if eq (slice . 0 9) "PASSWORD="}}{{slice . 9}}{{end}}{{end}}' msuite-browser 2>/dev/null || true)
fi

if [ -n "$EXISTING_PASSWORD" ] && [ "$EXISTING_PASSWORD" != "password123" ] && [ "${#EXISTING_PASSWORD}" -ge 8 ]; then
    USER_PASSWORD="$EXISTING_PASSWORD"
    echo "[*] Reusing existing secure password from running container."
else
    echo "Enter a secure password for your Virtual Browser (minimum 8 characters)."
    if [ -t 0 ]; then
        read -s -r -p "Password: " USER_PASSWORD
        echo ""
    else
        read -s -r USER_PASSWORD </dev/tty 2>/dev/null || USER_PASSWORD=""
        echo ""
    fi

    if [ -z "$USER_PASSWORD" ] || [ "$USER_PASSWORD" = "password123" ] || [ "${#USER_PASSWORD}" -lt 8 ]; then
        echo "[!] Invalid password. Password must be at least 8 characters and not 'password123'."
        echo "    Tip: Generate a strong password with: openssl rand -base64 16"
        exit 1
    fi
fi

# 5. Build Docker image
echo ""
echo "[*] Building MSuite-Browser Docker image..."
sudo docker build -t msuite-browser .

# 6. Stop and remove legacy or existing containers
for c in vbrowser msuite-browser; do
    if sudo docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "[*] Stopping existing container: ${c}..."
        sudo docker rm -f "${c}" >/dev/null 2>&1 || true
    fi
done

# 7. Start container
echo ""
echo "[*] Starting MSuite-Browser container..."
sudo docker run -d \
    --name msuite-browser \
    -p 3000:3000 \
    -e PASSWORD="$USER_PASSWORD" \
    -e ALLOW_PRIVATE_NAV=1 \
    -e TRUST_PROXY=0 \
    -v "$(pwd)/browser_data:/usr/src/app/browser_data" \
    --shm-size 2g \
    --restart unless-stopped \
    msuite-browser

# 8. Verification & Status Check
sleep 3
if sudo docker ps --format '{{.Names}}' | grep -q "^msuite-browser$"; then
    echo ""
    echo "=========================================================="
    echo "  INSTALLATION COMPLETE!                                  "
    echo "=========================================================="
    echo ""
    echo "  Container: msuite-browser (healthy and running)"
    echo "  Web Port:  http://localhost:3000"
    echo "  Password:  (configured)"
    echo ""
    echo "  For production, deploy behind Nginx or Caddy with TLS"
    echo "  and WebSocket upgrade headers, then pass TRUST_PROXY=1:"
    echo "    proxy_http_version 1.1;"
    echo "    proxy_set_header Upgrade \$http_upgrade;"
    echo "    proxy_set_header Connection \"upgrade\";"
    echo "    proxy_set_header X-Forwarded-Proto \$scheme;"
    echo "    proxy_set_header X-Forwarded-Host \$host;"
    echo "=========================================================="
else
    echo ""
    echo "[!] Container failed to start. Review logs with:"
    echo "    sudo docker logs msuite-browser"
    exit 1
fi
