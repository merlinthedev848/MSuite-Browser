# Use the official Node.js image based on Debian 12 (Bookworm - which is currently the most stable standard. Debian 13 "Trixie" is currently testing, but Bookworm packages are extremely compatible, or we can specify node:20-bookworm)
FROM node:20-bookworm

# Set working directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install application dependencies
RUN npm install

# Install system fonts and Tor onion routing proxy
RUN apt-get update && apt-get install -y \
    fonts-liberation \
    fonts-dejavu \
    fonts-noto-color-emoji \
    fontconfig \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright official Google Chrome with system dependencies
RUN npx playwright install chrome --with-deps

# Copy application source code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Start the Tor service in the background and launch the app
CMD [ "sh", "-c", "tor & node server.js" ]
