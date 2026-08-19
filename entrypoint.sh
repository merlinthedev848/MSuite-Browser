#!/bin/sh
# entrypoint.sh — Bootstrap Cloudflare WARP in SOCKS5 proxy mode, then start the app.
# WARP proxy mode requires NO special Linux capabilities (no NET_ADMIN, no TUN device).
# It runs entirely in userspace and exposes a local SOCKS5 proxy on port 40000.

WARP_PROXY_PORT=40000
WARP_READY=0

echo "[warp] Starting warp-svc daemon..."
warp-svc &
WARP_PID=$!

# Wait for warp-svc socket to become available (up to 15s)
for i in $(seq 1 30); do
    if warp-cli --accept-tos status > /dev/null 2>&1; then
        echo "[warp] warp-svc is responsive."
        WARP_READY=1
        break
    fi
    sleep 0.5
done

if [ "$WARP_READY" = "1" ]; then
    # Register a new anonymous device (free, no account required)
    warp-cli --accept-tos registration new 2>/dev/null || true

    # Switch to proxy-only mode (exposes SOCKS5 — no TUN, no NET_ADMIN needed)
    warp-cli --accept-tos mode proxy || true
    warp-cli --accept-tos proxy port $WARP_PROXY_PORT || true

    # Connect WARP
    warp-cli --accept-tos connect || true

    # Wait for WARP to report connected (up to 20s)
    for i in $(seq 1 40); do
        STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "")
        if echo "$STATUS" | grep -qi "connected"; then
            echo "[warp] ✅ Cloudflare WARP connected. SOCKS5 proxy on 127.0.0.1:$WARP_PROXY_PORT"
            break
        fi
        sleep 0.5
    done
else
    echo "[warp] ⚠️  warp-svc did not respond in time. VPN toggle will be unavailable."
fi

echo "[app] Starting Virtual Browser server..."
exec node /usr/src/app/server.js
