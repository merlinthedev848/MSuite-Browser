FROM node:20-bookworm

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

# ---- System fonts ----
RUN apt-get update && apt-get install -y \
    fonts-liberation \
    fonts-dejavu \
    fonts-noto-color-emoji \
    fontconfig \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ---- Cloudflare WARP (free built-in VPN, SOCKS5 proxy mode — no NET_ADMIN needed) ----
RUN curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
    | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" \
    > /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update && apt-get install -y cloudflare-warp \
    && rm -rf /var/lib/apt/lists/*

# ---- Playwright Google Chrome (proprietary codecs for NVR/H.264) ----
RUN npx playwright install chrome --with-deps

COPY . .
RUN sed -i 's/\r$//' /usr/src/app/entrypoint.sh && chmod +x /usr/src/app/entrypoint.sh

EXPOSE 3000

# entrypoint.sh bootstraps WARP in SOCKS5 proxy mode then starts the app
CMD [ "sh", "/usr/src/app/entrypoint.sh" ]
