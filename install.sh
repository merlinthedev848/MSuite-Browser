#!/bin/bash
set -euo pipefail

echo "==================================================="
echo "  Virtual Browser - Quick Install for Debian       "
echo "==================================================="

# Guard: if this file was saved from a GitHub 404 (private/raw URL without auth), abort early.
if ! head -1 "$0" | grep -q '^#!/bin/bash'; then
    echo "[!] This install.sh does not look like a valid script."
    echo "    If you used wget/curl against raw.githubusercontent.com and the repo is"
    echo "    private, you likely saved a '404: Not Found' body. Clone with git auth instead:"
    echo "      git clone https://github.com/merlinthedev848/browser.git virtual-browser"
    echo "      cd virtual-browser && ./install.sh"
    exit 1
fi

# 1. Install system dependencies
echo "[*] Installing required system packages (Git & Docker)..."
sudo apt-get update -y -q
sudo apt-get install -y git docker.io curl

# Ensure Docker is enabled and running
sudo systemctl enable --now docker

# 2. Clone or update the repository
REPO_URL="https://github.com/merlinthedev848/browser.git"
INSTALL_DIR="virtual-browser"

# If we are already inside a clone of this repo, update in place instead of nesting
if [ -f "./server.js" ] && [ -f "./Dockerfile" ] && [ -d "./.git" ]; then
    echo "[*] Running from an existing repo checkout — updating this directory..."
    git fetch origin main
    git reset --hard origin/main
    INSTALL_DIR="."
fi

if [ "$INSTALL_DIR" != "." ]; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "[*] Existing installation found — updating to latest version..."
        cd "$INSTALL_DIR"
        git fetch origin main
        git reset --hard origin/main
    else
        echo "[*] Cloning the Virtual Browser repository..."
        if ! git clone "$REPO_URL" "$INSTALL_DIR"; then
            echo "[!] git clone failed. If the repo is private, authenticate first, e.g.:"
            echo "    git clone https://<TOKEN>@github.com/merlinthedev848/browser.git $INSTALL_DIR"
            exit 1
        fi
        cd "$INSTALL_DIR"
    fi
fi

# 3. Ensure persistent data directory exists
echo "[*] Setting up persistent storage..."
mkdir -p browser_data
chmod 700 browser_data

# 4. Ask for password (required — no insecure default)
echo ""
EXISTING_PASSWORD=""
if sudo docker ps -a --format '{{.Names}}' | grep -q "^vbrowser$"; then
    EXISTING_PASSWORD=$(sudo docker inspect --format='{{range .Config.Env}}{{if eq (slice . 0 9) "PASSWORD="}}{{slice . 9}}{{end}}{{end}}' vbrowser 2>/dev/null || true)
fi

if [ -n "$EXISTING_PASSWORD" ] && [ "$EXISTING_PASSWORD" != "password123" ]; then
    USER_PASSWORD="$EXISTING_PASSWORD"
    echo "[*] Reusing existing password from running container."
else
    echo "Enter a secure password for your Virtual Browser (min 8 characters)."
    echo "A blank password is not allowed."

    if [ -t 0 ]; then
        read -s -r USER_PASSWORD
        echo ""
    else
        read -s -r USER_PASSWORD </dev/tty 2>/dev/null || USER_PASSWORD=""
        echo ""
    fi

    if [ -z "$USER_PASSWORD" ] || [ "$USER_PASSWORD" = "password123" ] || [ "${#USER_PASSWORD}" -lt 8 ]; then
        echo "[!] Invalid password. Generate one with: openssl rand -base64 18"
        exit 1
    fi
fi

# 5. Build Docker image
echo ""
echo "[*] Building Docker image (this may take a few minutes on first run)..."
sudo docker build -t virtual-browser .

# 6. Stop and remove any existing container
if sudo docker ps -a --format '{{.Names}}' | grep -q "^vbrowser$"; then
    echo "[*] Removing existing container..."
    sudo docker rm -f vbrowser
fi

# 7. Start the container
echo ""
echo "[*] Starting the Virtual Browser container..."
sudo docker run -d \
    --name vbrowser \
    -p 3000:3000 \
    -e PASSWORD="$USER_PASSWORD" \
    -e TRUST_PROXY=0 \
    -v "$(pwd)/browser_data:/usr/src/app/browser_data" \
    --shm-size 1g \
    --restart unless-stopped \
    virtual-browser

# 8. Wait briefly and confirm the container started
sleep 3
if sudo docker ps --format '{{.Names}}' | grep -q "^vbrowser$"; then
    echo ""
    echo "==================================================="
    echo "  INSTALLATION COMPLETE!                           "
    echo "==================================================="
    echo ""
    echo "  Container: vbrowser (running)"
    echo "  Port:      3000"
    echo "  Password:  (set — not printed)"
    echo ""
    echo "  Put this behind Nginx/Caddy with HTTPS + WebSocket"
    echo "  upgrade headers for production use:"
    echo "    proxy_http_version 1.1;"
    echo "    proxy_set_header Upgrade \$http_upgrade;"
    echo "    proxy_set_header Connection \"upgrade\";"
    echo "    proxy_set_header X-Forwarded-Proto \$scheme;"
    echo "  Then set TRUST_PROXY=1 on the container."
    echo "==================================================="
else
    echo ""
    echo "[!] Container failed to start. Check logs with:"
    echo "    docker logs vbrowser"
    exit 1
fi
