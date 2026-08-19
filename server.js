const express = require('express');
const { chromium } = require('playwright');
const { PlaywrightBlocker } = require('@ghostery/adblocker-playwright');
const fetch = require('cross-fetch');
const WebSocket = require('ws');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const PASSWORD = process.env.PASSWORD || 'password123';

// ---------- Global error protection ----------
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err.message, '\n', err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled rejection:', reason);
});

// ---------- HTTP / Express ----------
const validTokens = new Map(); // token -> { createdAt }
const loginAttempts = new Map(); // ip -> { count, lockUntil }

function getClientIp(req) {
    return req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
}

app.use(express.json({ limit: '1kb' })); // Restrict JSON payload size to prevent DoS

// Inject security headers to prevent clickjacking, MIME sniffing, and cross-site scripting
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;");
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/login', (req, res) => {
    const { password } = req.body || {};
    const ip = getClientIp(req);

    if (typeof password !== 'string' || password.length > 128) {
        return res.status(400).json({ success: false, error: 'Invalid payload structure' });
    }

    const attempt = loginAttempts.get(ip) || { count: 0, lockUntil: 0 };
    if (Date.now() < attempt.lockUntil) {
        const waitSec = Math.ceil((attempt.lockUntil - Date.now()) / 1000);
        return res.status(429).json({ 
            success: false, 
            error: `Too many failed attempts. Locked out for ${waitSec} seconds.` 
        });
    }

    const inputHash = crypto.createHash('sha256').update(password).digest();
    const expectedHash = crypto.createHash('sha256').update(PASSWORD).digest();
    const isMatched = crypto.timingSafeEqual(inputHash, expectedHash);

    if (isMatched) {
        loginAttempts.delete(ip);
        const token = crypto.randomBytes(32).toString('hex');
        validTokens.set(token, { createdAt: Date.now() });

        for (const [t, v] of validTokens) {
            if (Date.now() - v.createdAt > 86_400_000) validTokens.delete(t);
        }
        res.json({ success: true, token });
    } else {
        attempt.count++;
        if (attempt.count >= 5) {
            const lockoutDuration = 60_000 * Math.pow(2, attempt.count - 5);
            attempt.lockUntil = Date.now() + lockoutDuration;
        }
        loginAttempts.set(ip, attempt);

        res.status(401).json({ 
            success: false, 
            error: attempt.count >= 5 
                ? 'Invalid password. You are now temporarily locked out.' 
                : 'Invalid password' 
        });
    }
});

// ---------- WebSocket Server ----------
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
    const parsedUrl = url.parse(request.url, true);
    const token = parsedUrl.query.token;
    const isValid = token && validTokens.has(token);

    wss.handleUpgrade(request, socket, head, (ws) => {
        ws.isAuthorized = isValid;
        wss.emit('connection', ws, request);
    });
});

// ---------- Global Browser Instance & Adblocker ----------
let browser = null;
let adblocker = null;
let browserStarting = false;
let browserReady = false;

/** Send a frame to one client with explicit flow control */
function sendFrameToClient(ws, data) {
    if (ws.readyState !== WebSocket.OPEN) return;

    if (ws.ackTimeout) {
        clearTimeout(ws.ackTimeout);
        ws.ackTimeout = null;
    }

    if (!ws.frameInFlight) {
        ws.frameInFlight = true;
        const buffer = Buffer.from(data, 'base64');
        ws.send(buffer);

        // 1.5s fail-safe timeout to prevent stream freezing from dropped client acks
        ws.ackTimeout = setTimeout(() => {
            ws.frameInFlight = false;
            if (ws.lastFrameData) {
                const nextData = ws.lastFrameData;
                ws.lastFrameData = null;
                sendFrameToClient(ws, nextData);
            }
        }, 1500);
    } else {
        ws.lastFrameData = data;
    }
}

function sendTabState(ws) {
    if (ws.readyState !== WebSocket.OPEN) return;
    const tabList = Array.from(ws.tabs.entries()).map(([id, t]) => ({
        id,
        title: t.title,
        url: t.url,
        favicon: t.favicon,
        isActive: id === ws.activeTabId
    }));
    ws.send(JSON.stringify({ type: 'tab_state', tabs: tabList }));
}

// ---------- Screencast Control ----------
async function startScreencast(client) {
    await client.send('Page.startScreencast', {
        format: 'png',
        maxWidth: 1920,
        maxHeight: 1080,
        everyNthFrame: 1
    }).catch(() => {});
}

async function stopScreencast(client) {
    await client.send('Page.stopScreencast').catch(() => {});
}

async function renderErrorPage(page, url, errorMessage) {
    if (page.isClosed()) return;
    const errorHtml = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Navigation Error</title>
        <style>
            body {
                background-color: #0f172a;
                color: #f8fafc;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                padding: 20px;
                box-sizing: border-box;
            }
            .container {
                max-width: 500px;
                text-align: center;
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 32px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            }
            h1 {
                font-size: 22px;
                margin-top: 0;
                color: #ef4444;
            }
            p {
                font-size: 14px;
                color: #94a3b8;
                line-height: 1.6;
                word-break: break-all;
            }
            .url {
                font-family: monospace;
                background: #0f172a;
                padding: 6px 10px;
                border-radius: 6px;
                border: 1px solid #1e293b;
                margin: 16px 0;
            }
            .btn {
                background: #3b82f6;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.15s;
                margin-top: 16px;
            }
            .btn:hover {
                background: #2563eb;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Navigation Failed</h1>
            <p>The virtual browser was unable to load the requested website:</p>
            <div class="url">${url}</div>
            <p><strong>Error:</strong> ${errorMessage}</p>
            <button class="btn" onclick="location.reload()">Retry Connection</button>
        </div>
    </body>
    </html>
    `;
    await page.setContent(errorHtml).catch(() => {});
}

// ---------- Connection-scoped Tab Management ----------
async function createTab(ws) {
    const tabId = 'tab_' + (++ws.tabCounter);
    const page = await ws.context.newPage();

    // Spoof UA dynamically on page level
    const targetUA = ws.currentUserAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
    await page.addInitScript((ua) => {
        window.__customUA = ua;
    }, targetUA).catch(() => {});

    if (adblocker && ws.adblockerEnabled) {
        await adblocker.enableBlockingInPage(page).catch(() => {});
    }

    // Monitor page load events to broadcast load state to the client
    page.on('domcontentloaded', () => {
        if (tabId === ws.activeTabId && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'loading_state', loading: false }));
        }
    });
    page.on('load', () => {
        if (tabId === ws.activeTabId && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'loading_state', loading: false }));
        }
    });
    page.on('request', (req) => {
        try {
            if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
                if (tabId === ws.activeTabId && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'loading_state', loading: true }));
                }
            }
        } catch (_) {}
    });
    page.on('requestfailed', (req) => {
        try {
            if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
                if (tabId === ws.activeTabId && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'loading_state', loading: false }));
                }
            }
        } catch (_) {}
    });

    const client = await page.context().newCDPSession(page);
    await client.send('Page.enable');

    ws.tabs.set(tabId, { page, client, title: 'New Tab', url: 'about:blank', favicon: '' });

    page.on('framenavigated', (frame) => {
        if (frame !== page.mainFrame()) return;
        const t = ws.tabs.get(tabId);
        if (!t || page.isClosed()) return;

        t.url = frame.url();

        page.title()
            .then(title => { if (t) t.title = title || 'New Tab'; })
            .catch(() => {})
            .then(() => page.evaluate(() => {
                const el = document.querySelector("link[rel~='icon'], link[rel='shortcut icon']");
                return el ? el.href : (location.origin + '/favicon.ico');
            }))
            .then(fav => { if (t) t.favicon = fav || ''; })
            .catch(() => {})
            .finally(() => {
                sendTabState(ws);
                if (tabId === ws.activeTabId) {
                    ws.send(JSON.stringify({ type: 'url_changed', url: t.url }));
                }
            });
    });

    client.on('Page.screencastFrame', ({ data, sessionId }) => {
        client.send('Page.screencastFrameAck', { sessionId }).catch(() => {});
        if (tabId !== ws.activeTabId) return;
        sendFrameToClient(ws, data);
    });

    return tabId;
}

async function switchTab(ws, tabId) {
    if (!ws.tabs.has(tabId)) return;

    if (ws.activeTabId && ws.tabs.has(ws.activeTabId) && ws.activeTabId !== tabId) {
        await stopScreencast(ws.tabs.get(ws.activeTabId).client);
    }

    ws.activeTabId = tabId;
    const t = ws.tabs.get(tabId);

    ws.frameInFlight = false;
    ws.lastFrameData = null;

    sendTabState(ws);
    ws.send(JSON.stringify({ type: 'url_changed', url: t.url }));

    await startScreencast(t.client);
}

async function closeTab(ws, tabId) {
    if (!ws.tabs.has(tabId)) return;
    const t = ws.tabs.get(tabId);

    await stopScreencast(t.client);
    await t.page.close().catch(() => {});
    ws.tabs.delete(tabId);

    if (ws.activeTabId === tabId) {
        if (ws.tabs.size > 0) {
            await switchTab(ws, Array.from(ws.tabs.keys()).pop());
        } else {
            ws.activeTabId = null;
            sendTabState(ws);
            const newId = await createTab(ws);
            await switchTab(ws, newId);
            const p = ws.tabs.get(newId).page;
            p.goto('https://www.google.com').catch(e => console.warn(`[nav] ${e.message}`));
        }
    } else {
        sendTabState(ws);
    }
}

// ---------- Browser Lifecycle ----------
async function startBrowser() {
    if (browserReady || browserStarting) return;
    browserStarting = true;

    try {
        console.log('[*] Loading adblocker engine...');
        const cacheDir = path.join(__dirname, 'adblocker_cache');
        fs.mkdirSync(cacheDir, { recursive: true });
        const cachePath = path.join(cacheDir, 'adblocker.bin');

        adblocker = await PlaywrightBlocker.fromPrebuiltAdsAndTracking(fetch, {
            path: cachePath,
            read: async (p) => fs.promises.readFile(p),
            write: async (p, content) => fs.promises.writeFile(p, content)
        }).catch(e => {
            console.warn('[!] Adblocker failed to load:', e.message);
            return null;
        });

        console.log('[*] Launching Chromium...');
        browser = await chromium.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-accelerated-2d-canvas',
                '--enable-font-antialiasing',
                '--font-render-hinting=medium',
                '--subpixel-text-rendering',
                '--force-color-profile=srgb'
            ]
        });

        browserReady = true;
        browserStarting = false;
        console.log('[*] Browser ready.');
    } catch (err) {
        browserStarting = false;
        throw err;
    }
}

// Pre-start browser at server boot
startBrowser().catch(err => {
    console.error('[!] Pre-warm failed, will retry on first connection:', err.message);
});

// ---------- WebSocket Connection Handler ----------
wss.on('connection', async (ws) => {
    if (!ws.isAuthorized) {
        ws.send(JSON.stringify({ type: 'auth_error', error: 'Session expired. Please log in again.' }));
        ws.close(4001, 'Unauthorized');
        return;
    }
    console.log('[+] Client connected');

    // Setup connection-scoped state
    ws.frameInFlight = false;
    ws.lastFrameData = null;
    ws.tabs = new Map();
    ws.activeTabId = null;
    ws.tabCounter = 0;
    ws.adblockerEnabled = true;
    ws.currentUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    let waited = 0;
    while (browserStarting && waited < 60_000) {
        await new Promise(r => setTimeout(r, 250));
        waited += 250;
    }

    if (!browserReady) {
        console.log('[*] Browser not ready, starting now...');
        try {
            await startBrowser();
        } catch (err) {
            console.error('[!] startBrowser failed:', err.message);
            ws.close(1011, 'Browser failed to start');
            return;
        }
    }

    // Create client-isolated BrowserContext
    try {
        ws.context = await browser.newContext({
            viewport: { width: 1920, height: 1080 },
            deviceScaleFactor: 1,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            locale: 'en-US',
            timezoneId: 'Europe/London'
        });

        // Set up cursor reporting binding for this client's context
        await ws.context.exposeBinding('__reportCursor', (source, cursor) => {
            if (source.page.isClosed()) return;
            const tab = Array.from(ws.tabs.values()).find(t => t.page === source.page);
            if (tab && ws.activeTabId && ws.tabs.get(ws.activeTabId) === tab) {
                ws.send(JSON.stringify({ type: 'cursor', cursor }));
            }
        });

        // Set up clipboard reporting binding for this client's context
        await ws.context.exposeBinding('__reportCopy', (source, text) => {
            if (source.page.isClosed()) return;
            ws.send(JSON.stringify({ type: 'clipboard', text }));
        });

        await ws.context.addInitScript(() => {
            // Anti-detection: Hide webdriver parameter
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

            document.addEventListener('mouseover', (e) => {
                try {
                    window.__reportCursor(window.getComputedStyle(e.target).cursor);
                } catch (_) {}
            }, { passive: true, capture: true });

            document.addEventListener('copy', () => {
                try {
                    const selected = window.getSelection().toString();
                    if (selected) window.__reportCopy(selected);
                } catch (_) {}
            }, { passive: true, capture: true });
        });
    } catch (err) {
        console.error('[!] Failed to create browser context:', err.message);
        ws.close(1011, 'Failed to initialize session');
        return;
    }

    // Initialize first tab for this connection
    const tabId = await createTab(ws);
    await switchTab(ws, tabId);
    const initialPage = ws.tabs.get(tabId).page;
    initialPage.goto('https://www.google.com').catch(e => console.warn(`[nav] ${e.message}`));

    ws.on('message', async (raw) => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        // --- Payload Validation & Sanitation ---
        try {
            if (!msg || typeof msg.type !== 'string') return;

            if (msg.type === 'mousemove' || msg.type === 'mousedown' || msg.type === 'mouseup') {
                if (typeof msg.x !== 'number' || typeof msg.y !== 'number') return;
                msg.x = Math.max(0, Math.min(1920, Math.round(msg.x)));
                msg.y = Math.max(0, Math.min(1080, Math.round(msg.y)));
                if (msg.button && !['left', 'middle', 'right'].includes(msg.button)) return;
            } else if (msg.type === 'wheel') {
                if (typeof msg.deltaX !== 'number' || typeof msg.deltaY !== 'number') return;
                msg.deltaX = Math.max(-5000, Math.min(5000, msg.deltaX));
                msg.deltaY = Math.max(-5000, Math.min(5000, msg.deltaY));
            } else if (msg.type === 'keydown' || msg.type === 'keyup') {
                if (typeof msg.key !== 'string' || msg.key.length > 50) return;
                if (msg.modifiers && (!Array.isArray(msg.modifiers) || msg.modifiers.some(m => typeof m !== 'string' || m.length > 20))) return;
            } else if (msg.type === 'goto') {
                if (typeof msg.url !== 'string' || msg.url.length > 2048) return;
            } else if (msg.type === 'type') {
                if (typeof msg.text !== 'string' || msg.text.length > 10000) return;
            } else if (msg.type === 'new_tab') {
                if (msg.url && (typeof msg.url !== 'string' || msg.url.length > 2048)) return;
            } else if (msg.type === 'switch_tab' || msg.type === 'close_tab') {
                if (typeof msg.tabId !== 'string' || !/^tab_\d+$/.test(msg.tabId)) return;
            } else if (msg.type === 'toggle_adblocker') {
                if (typeof msg.enabled !== 'boolean') return;
            } else if (msg.type === 'set_useragent') {
                if (typeof msg.userAgent !== 'string' || msg.userAgent.length > 512) return;
            }
        } catch {
            return;
        }

        try {
            if (msg.type === 'frame_ack') {
                if (ws.ackTimeout) {
                    clearTimeout(ws.ackTimeout);
                    ws.ackTimeout = null;
                }
                ws.frameInFlight = false;
                if (ws.lastFrameData) {
                    const data = ws.lastFrameData;
                    ws.lastFrameData = null;
                    sendFrameToClient(ws, data);
                }
                return;
            }

            if (msg.type === 'new_tab') {
                const id = await createTab(ws);
                await switchTab(ws, id);
                const p = ws.tabs.get(id).page;
                p.goto(msg.url || 'https://www.google.com').catch(e => {
                    console.warn(`[nav] ${e.message}`);
                    renderErrorPage(p, msg.url || 'https://www.google.com', e.message);
                });
                return;
            }
            if (msg.type === 'switch_tab') { await switchTab(ws, msg.tabId); return; }
            if (msg.type === 'close_tab')  { await closeTab(ws, msg.tabId);  return; }

            // Session Settings handlers
            if (msg.type === 'clear_session') {
                if (ws.context) {
                    await ws.context.clearCookies().catch(() => {});
                    for (const tab of ws.tabs.values()) {
                        tab.page.reload().catch(() => {});
                    }
                    console.log('[session] Cleared all session cookies and reloaded pages.');
                }
                return;
            }

            if (msg.type === 'toggle_adblocker') {
                ws.adblockerEnabled = msg.enabled;
                if (adblocker) {
                    for (const tab of ws.tabs.values()) {
                        if (msg.enabled) {
                            await adblocker.enableBlockingInPage(tab.page).catch(() => {});
                        } else {
                            await adblocker.disableBlockingInPage(tab.page).catch(() => {});
                        }
                    }
                }
                console.log(`[session] Adblocker state toggled to: ${msg.enabled}`);
                return;
            }

            if (msg.type === 'set_useragent') {
                const profiles = {
                    desktop: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
                    mobile: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'
                };
                const targetUA = profiles[msg.userAgent] || msg.userAgent;
                ws.currentUserAgent = targetUA;

                for (const tab of ws.tabs.values()) {
                    await tab.page.evaluate((ua) => {
                        window.__customUA = ua;
                    }, targetUA).catch(() => {});
                    tab.page.reload().catch(() => {});
                }
                console.log(`[session] User-Agent updated to: ${targetUA}`);
                return;
            }

            if (!ws.activeTabId || !ws.tabs.has(ws.activeTabId)) return;
            const p = ws.tabs.get(ws.activeTabId).page;
            if (p.isClosed()) return;

            switch (msg.type) {
                case 'mousemove':
                    p.mouse.move(msg.x, msg.y).catch(() => {});
                    break;
                case 'mousedown':
                    console.log(`[ws] Click down at (${msg.x}, ${msg.y}) button: ${msg.button}`);
                    p.mouse.move(msg.x, msg.y).catch(() => {});
                    p.mouse.down({ button: msg.button || 'left' }).catch(() => {});
                    break;
                case 'mouseup':
                    console.log(`[ws] Click up at (${msg.x}, ${msg.y}) button: ${msg.button}`);
                    p.mouse.move(msg.x, msg.y).catch(() => {});
                    p.mouse.up({ button: msg.button || 'left' }).catch(() => {});
                    break;

                case 'keydown': {
                    if (msg.modifiers?.length) {
                        for (const mod of msg.modifiers) {
                            if (mod !== msg.key) await p.keyboard.down(mod).catch(() => {});
                        }
                    }
                    await p.keyboard.down(msg.key).catch(() => {});
                    break;
                }
                case 'keyup': {
                    await p.keyboard.up(msg.key).catch(() => {});
                    if (msg.modifiers?.length) {
                        for (const mod of msg.modifiers) {
                            if (mod !== msg.key) await p.keyboard.up(mod).catch(() => {});
                        }
                    }
                    break;
                }

                case 'wheel':
                    p.mouse.wheel(msg.deltaX || 0, msg.deltaY || 0).catch(() => {});
                    break;

                case 'goto': {
                    if (!msg.url) break;
                    let target = msg.url.trim();
                    console.log(`[ws] URL request: "${target}"`);
                    
                    let isAutoprepended = false;
                    if (!/^https?:\/\//i.test(target)) {
                        const looksLikeIp = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/.test(target);
                        const looksLikeDomain = looksLikeIp
                            || /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/.test(target)
                            || target.toLowerCase().startsWith('localhost')
                            || target.startsWith('127.0.0.1');

                        if (looksLikeDomain) {
                            const useHttp = looksLikeIp 
                                || target.toLowerCase().startsWith('localhost') 
                                || target.startsWith('127.0.0.1');
                            target = (useHttp ? 'http://' : 'https://') + target;
                            isAutoprepended = !useHttp;
                        } else {
                            target = 'https://www.google.com/search?q=' + encodeURIComponent(target);
                        }
                    }
                    console.log(`[ws] Final resolved navigation target: "${target}"`);
                    
                    const activePage = p;
                    activePage.goto(target).catch(async (e) => {
                        console.warn(`[nav] ${e.message}`);
                        if (isAutoprepended && target.startsWith('https://')) {
                            const fallbackUrl = target.replace('https://', 'http://');
                            console.log(`[ws] HTTPS failed, trying HTTP fallback: "${fallbackUrl}"`);
                            await activePage.goto(fallbackUrl).catch(err => {
                                console.warn(`[nav fallback] ${err.message}`);
                                renderErrorPage(activePage, target, err.message);
                            });
                        } else {
                            renderErrorPage(activePage, target, e.message);
                        }
                    });
                    break;
                }

                case 'type':
                    p.keyboard.type(msg.text).catch(() => {});
                    break;

                case 'back':
                    p.goBack().catch(() => {});
                    break;

                case 'forward':
                    p.goForward().catch(() => {});
                    break;

                case 'reload':
                    p.reload().catch(() => {});
                    break;
            }
        } catch (err) {
            console.error('[!] Message handler error:', err.message);
        }
    });

    ws.on('close', async () => {
        console.log('[-] Client disconnected');
        if (ws.ackTimeout) {
            clearTimeout(ws.ackTimeout);
            ws.ackTimeout = null;
        }
        // Close browser context associated with this client to clear memory, history, cookies, and localstorage
        if (ws.context) {
            await ws.context.close().catch(() => {});
        }
    });

    ws.on('error', (err) => {
        console.error('[!] WebSocket error:', err.message);
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[*] Virtual Browser listening on 0.0.0.0:${PORT}`);
});
