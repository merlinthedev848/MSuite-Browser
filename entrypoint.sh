#!/bin/sh
# entrypoint.sh — Optionally bootstrap Cloudflare WARP (SOCKS5), then start the app.

WARP_PROXY_PORT=40000
WARP_READY=0
ENABLE_WARP="${ENABLE_WARP:-1}"

if [ -z "${PASSWORD:-}" ] || [ "$PASSWORD" = "password123" ]; then
    echo "[FATAL] PASSWORD env var must be set to a non-default value (8+ chars)."
    exit 1
fi

if [ "$ENABLE_WARP" = "1" ] && command -v warp-svc >/dev/null 2>&1 && command -v warp-cli >/dev/null 2>&1; then
    echo "[warp] Starting warp-svc daemon..."
    warp-svc &
    WARP_PID=$!

    for i in $(seq 1 30); do
        if warp-cli --accept-tos status > /dev/null 2>&1; then
            echo "[warp] warp-svc is responsive."
            WARP_READY=1
            break
        fi
        sleep 0.5
    done

    if [ "$WARP_READY" = "1" ]; then
        warp-cli --accept-tos registration new 2>/dev/null || true
        warp-cli --accept-tos mode proxy || true
        warp-cli --accept-tos proxy port "$WARP_PROXY_PORT" || true
        warp-cli --accept-tos connect || true

        for i in $(seq 1 40); do
            STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "")
            if echo "$STATUS" | grep -qi "connected"; then
                echo "[warp] Cloudflare WARP connected. SOCKS5 on 127.0.0.1:$WARP_PROXY_PORT"
                break
            fi
            sleep 0.5
        done
    else
        echo "[warp] warp-svc did not respond in time. VPN toggle may be unavailable."
    fi
else
    echo "[warp] Skipped (ENABLE_WARP=$ENABLE_WARP or warp not installed)."
fi

echo "[app] Starting Virtual Browser server..."
exec node /usr/src/app/server.js
