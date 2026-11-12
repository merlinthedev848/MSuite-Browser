FROM node:20-bookworm

WORKDIR /usr/src/app

# Reproducible installs when lockfile is present
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# ---- System fonts + curl/gnupg for optional WARP ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation \
    fonts-dejavu \
    fonts-noto-color-emoji \
    fontconfig \
    curl \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ---- Optional Cloudflare WARP (amd64 only; skipped on other arches) ----
ARG ENABLE_WARP=1
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ENABLE_WARP" = "1" ] && [ "$ARCH" = "amd64" ]; then \
      curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg; \
      echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" \
        > /etc/apt/sources.list.d/cloudflare-client.list; \
      apt-get update && apt-get install -y --no-install-recommends cloudflare-warp; \
      rm -rf /var/lib/apt/lists/*; \
    else \
      echo "WARP install skipped (ENABLE_WARP=$ENABLE_WARP arch=$ARCH)"; \
    fi

# ---- Playwright Google Chrome (proprietary codecs) ----
RUN npx playwright install chrome --with-deps

COPY . .
RUN sed -i 's/\r$//' /usr/src/app/entrypoint.sh && chmod +x /usr/src/app/entrypoint.sh \
    && mkdir -p /usr/src/app/browser_data /usr/src/app/adblocker_cache

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1

CMD [ "sh", "/usr/src/app/entrypoint.sh" ]
