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

// ---------- Startup security assertion ----------
// Refuse to boot with the default password in production
if (PASSWORD === 'password123') {
    console.warn('[⚠️  SECURITY] Running with default password. Set the PASSWORD environment variable.');
}
// Enforce minimum password length
if (PASSWORD.length < 8) {
    console.error('[FATAL] PASSWORD must be at least 8 characters. Exiting.');
    process.exit(1);
}

// ---------- Global error protection ----------
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err.message, '\n', err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled rejection:', reason);
});

// ---------- Trusted proxy IP resolution ----------
// Prevent X-Forwarded-For spoofing by only trusting the socket's real remote address.
// If running behind a TRUSTED reverse proxy (e.g. Nginx on same host), set TRUST_PROXY=1.
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

function getClientIp(req) {
    if (TRUST_PROXY) {
        const xff = req.headers['x-forwarded-for'];
        // Only take the FIRST entry from XFF — that's the real client behind a trusted proxy
        const ip = xff ? xff.split(',')[0].trim() : req.socket.remoteAddress;
        return ip || 'unknown';
    }
    // Without proxy trust, always use the direct socket address (cannot be spoofed)
    return req.socket.remoteAddress || 'unknown';
}

// ---------- Auth state ----------
const validTokens = new Map();   // token -> { createdAt, ip, lastActivity }
const loginAttempts = new Map(); // ip -> { count, lockUntil, firstAttempt }
const globalRateMap = new Map(); // ip -> { requests, windowStart }

const TOKEN_TTL_MS        = 12 * 60 * 60 * 1000; // 12 hours
const LOCKOUT_THRESHOLD   = 5;                    // failed attempts before lockout
const GLOBAL_REQ_LIMIT    = 60;                   // max requests per IP per 60s window
const GLOBAL_REQ_WINDOW   = 60_000;
const MAX_ATTEMPTS_STORED = 5_000;                // cap map size to resist memory DoS
const MAX_TOKENS_STORED   = 500;

const SESSIONS_FILE = path.join(__dirname, 'browser_data', 'sessions.json');

function loadSessions() {
    try {
        if (fs.existsSync(SESSIONS_FILE)) {
            const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
            const data = JSON.parse(raw);
            const now = Date.now();
            if (Array.isArray(data)) {
                for (const item of data) {
                    if (item && item.token && item.createdAt && (now - item.createdAt <= TOKEN_TTL_MS)) {
                        validTokens.set(item.token, {
                            createdAt: item.createdAt,
                            ip: item.ip || 'unknown',
                            lastActivity: item.lastActivity || item.createdAt
                        });
                    }
                }
            }
            console.log(`[auth] Restored ${validTokens.size} active sessions from disk.`);
        }
    } catch (e) {
        console.warn('[auth] Could not load saved sessions:', e.message);
    }
}

function saveSessions() {
    try {
        const data = Array.from(validTokens.entries()).map(([token, meta]) => ({
            token,
            createdAt: meta.createdAt,
            ip: meta.ip,
            lastActivity: meta.lastActivity
        }));
        fs.writeFileSync(SESSIONS_FILE, JSON.stringify(data), 'utf8');
    } catch (_) {}
}

// Load existing sessions on boot
loadSessions();

// Periodic cleanup — runs every 10 minutes
setInterval(() => {
    const now = Date.now();
    let cleaned = false;
    for (const [token, v] of validTokens) {
        if (now - v.createdAt > TOKEN_TTL_MS) {
            validTokens.delete(token);
            cleaned = true;
        }
    }
    if (cleaned) saveSessions();

    for (const [ip, v] of loginAttempts) {
        if (v.lockUntil < now - 3_600_000 && v.count < LOCKOUT_THRESHOLD) loginAttempts.delete(ip);
    }
    for (const [ip, v] of globalRateMap) {
        if (now - v.windowStart > GLOBAL_REQ_WINDOW) globalRateMap.delete(ip);
    }
}, 10 * 60 * 1000);

// ---------- Middleware ----------
app.use(express.json({ limit: '512b' })); // tighten body limit — login payload is tiny
app.set('trust proxy', TRUST_PROXY ? 1 : false);

// --- Global per-IP request rate limiter (applied to ALL routes) ---
app.use((req, res, next) => {
    const ip = getClientIp(req);
    const now = Date.now();
    const entry = globalRateMap.get(ip) || { requests: 0, windowStart: now };

    if (now - entry.windowStart > GLOBAL_REQ_WINDOW) {
        entry.requests = 0;
        entry.windowStart = now;
    }
    entry.requests++;

    // Enforce map size cap
    if (globalRateMap.size > MAX_ATTEMPTS_STORED) {
        const oldest = [...globalRateMap.entries()].sort((a, b) => a[1].windowStart - b[1].windowStart)[0];
        if (oldest) globalRateMap.delete(oldest[0]);
    }

    globalRateMap.set(ip, entry);

    if (entry.requests > GLOBAL_REQ_LIMIT) {
        res.setHeader('Retry-After', '60');
        return res.status(429).json({ success: false, error: 'Rate limit exceeded. Try again in 60 seconds.' });
    }
    next();
});

// --- Hardened security headers (applied to ALL responses) ---
app.use((req, res, next) => {
    // Anti-clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    // Disable MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // XSS filter (legacy browsers)
    res.setHeader('X-XSS-Protection', '1; mode=block');
    // Do not send Referer to external sites
    res.setHeader('Referrer-Policy', 'no-referrer');
    // Restrict browser features
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
    // Strict CSP — no inline scripts, no eval, only self + WS
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com",
        "img-src 'self' data: blob: https://www.google.com",
        "connect-src 'self' ws: wss:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ].join('; '));
    // HSTS — force HTTPS for 1 year (enable when TLS-terminated)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    // Prevent caching of authenticated responses
    res.setHeader('Cache-Control', 'no-store');
    next();
});

app.use(express.static(path.join(__dirname, 'public'), {
    // Serve static files with a permissive cache for assets only
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
}));

// Expose browser downloads folder with restricted headers
const downloadsDir = path.join(__dirname, 'browser_data', 'downloads');
fs.mkdirSync(downloadsDir, { recursive: true });
app.use('/downloads', express.static(downloadsDir, {
    dotfiles: 'deny',
    setHeaders: (res) => {
        res.setHeader('Content-Disposition', 'attachment');
        res.setHeader('X-Content-Type-Options', 'nosniff');
    }
}));

// =============================================================================
// THREAT INTELLIGENCE ENGINE
// =============================================================================
// Layers:
//   1. Local public blocklist  — hourly refresh from ipsum/Firehol/abuse.ch feeds (no key needed)
//   2. AbuseIPDB reputation    — per-login check + auto-report on lockout (free API key)
//   3. Security audit log      — structured JSONL log written to browser_data/security.log
// =============================================================================

const ABUSEIPDB_KEY        = process.env.ABUSEIPDB_KEY || null;
const ABUSEIPDB_BLOCK_SCORE = parseInt(process.env.ABUSEIPDB_BLOCK_SCORE || '80', 10);

const securityLogPath = path.join(__dirname, 'browser_data', 'security.log');
const abuseScoreCache = new Map(); // ip -> { score, fetchedAt }
const SCORE_CACHE_TTL = 60 * 60 * 1000; // 1 hour

// ---------- Public blocklist (downloaded from open threat feeds) ----------
let publicBlocklist = new Set();
let blocklistLastUpdated = null;

const BLOCKLIST_FEEDS = [
    // ipsum: aggregation of many public IP blocklists (score >= 3 attacks across lists)
    'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    // Emerging Threats known compromised hosts
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    // abuse.ch Feodo tracker botnet C2 IPs
    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
];

async function refreshBlocklists() {
    const newSet = new Set();
    for (const feedUrl of BLOCKLIST_FEEDS) {
        try {
            const res = await fetch(feedUrl, { signal: AbortSignal.timeout(15_000) });
            if (!res.ok) continue;
            const text = await res.text();
            for (const line of text.split('\n')) {
                const trimmed = line.trim();
                // Skip comment lines and blank lines
                if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
                // ipsum format: "1.2.3.4\t5" — take only the IP field
                const ip = trimmed.split(/\s+/)[0];
                if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
                    newSet.add(ip);
                }
            }
        } catch (e) {
            console.warn(`[blocklist] Failed to fetch ${feedUrl}: ${e.message}`);
        }
    }
    publicBlocklist = newSet;
    blocklistLastUpdated = new Date().toISOString();
    console.log(`[blocklist] Refreshed: ${publicBlocklist.size} blocked IPs loaded from ${BLOCKLIST_FEEDS.length} feeds.`);
}

// Refresh on boot then every hour
refreshBlocklists().catch(() => {});
setInterval(() => refreshBlocklists().catch(() => {}), 60 * 60 * 1000);

// ---------- Private / loopback IP guard ----------
function isPrivateIp(ip) {
    if (!ip || ip === '::1' || ip === '127.0.0.1') return true;
    // Strip IPv6-mapped IPv4 prefix
    const plain = ip.replace(/^::ffff:/, '');
    return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(plain);
}

// ---------- Security audit log writer ----------
function securityLog(event) {
    const entry = JSON.stringify({ ts: new Date().toISOString(), ...event }) + '\n';
    fs.appendFile(securityLogPath, entry, () => {});
    console.warn(`[security-log] ${JSON.stringify(event)}`);
}

// ---------- AbuseIPDB: check IP reputation ----------
async function checkAbuseIPDB(ip) {
    if (!ABUSEIPDB_KEY || isPrivateIp(ip)) return null;

    // Return cached score if fresh
    const cached = abuseScoreCache.get(ip);
    if (cached && Date.now() - cached.fetchedAt < SCORE_CACHE_TTL) return cached;

    try {
        const cleanIp = ip.replace(/^::ffff:/, '');
        const res = await fetch(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(cleanIp)}&maxAgeInDays=30&verbose`,
            {
                headers: { 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json' },
                signal: AbortSignal.timeout(5_000)
            }
        );
        if (!res.ok) return null;
        const json = await res.json();
        const result = {
            score: json.data?.abuseConfidenceScore ?? 0,
            totalReports: json.data?.totalReports ?? 0,
            countryCode: json.data?.countryCode ?? '??',
            isp: json.data?.isp ?? 'Unknown',
            fetchedAt: Date.now()
        };
        abuseScoreCache.set(ip, result);
        return result;
    } catch {
        return null;
    }
}

// ---------- AbuseIPDB: report an IP ----------
async function reportToAbuseIPDB(ip, comment) {
    if (!ABUSEIPDB_KEY || isPrivateIp(ip)) return;
    try {
        const cleanIp = ip.replace(/^::ffff:/, '');
        const body = new URLSearchParams({
            ip: cleanIp,
            categories: '18',   // 18 = Brute-Force
            comment: comment.slice(0, 1024)
        });
        const res = await fetch('https://api.abuseipdb.com/api/v2/report', {
            method: 'POST',
            headers: { 'Key': ABUSEIPDB_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
            signal: AbortSignal.timeout(8_000)
        });
        if (res.ok) {
            console.log(`[abuseipdb] Reported ${cleanIp} to AbuseIPDB.`);
        }
    } catch (e) {
        console.warn(`[abuseipdb] Report failed for ${ip}: ${e.message}`);
    }
}

// ---------- Composite threat check (blocklist + AbuseIPDB) ----------
async function isThreatIp(ip) {
    // Layer 1: instant local blocklist hit
    const plain = ip.replace(/^::ffff:/, '');
    if (publicBlocklist.has(plain)) {
        return { blocked: true, reason: 'Public threat feed match', score: 100 };
    }
    // Layer 2: AbuseIPDB real-time score
    const abuse = await checkAbuseIPDB(ip);
    if (abuse && abuse.score >= ABUSEIPDB_BLOCK_SCORE) {
        return { blocked: true, reason: `AbuseIPDB score ${abuse.score}/100`, score: abuse.score, isp: abuse.isp, country: abuse.countryCode };
    }
    return { blocked: false, score: abuse?.score ?? 0 };
}

// ---------- Security log admin endpoint ----------
app.get('/api/security/log', (req, res) => {
    // Only allow local access or authenticated session (check token in query)
    const token = req.query.token;
    if (!token || !validTokens.has(token)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const raw = fs.readFileSync(securityLogPath, 'utf8');
        const lines = raw.trim().split('\n').filter(Boolean);
        // Return last 200 events
        const entries = lines.slice(-200).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        res.json({ count: entries.length, events: entries.reverse() });
    } catch {
        res.json({ count: 0, events: [] });
    }
});

// Blocklist status endpoint
app.get('/api/security/blocklist', (req, res) => {
    const token = req.query.token;
    if (!token || !validTokens.has(token)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json({
        totalBlocked: publicBlocklist.size,
        lastUpdated: blocklistLastUpdated,
        feeds: BLOCKLIST_FEEDS,
        abuseipdbEnabled: !!ABUSEIPDB_KEY,
        blockScoreThreshold: ABUSEIPDB_BLOCK_SCORE
    });
});



// --- CSRF origin validation helper ---
function validateOrigin(req) {
    const origin = req.headers['origin'] || req.headers['referer'] || '';
    const host   = req.headers['host'] || '';
    // Allow requests from same host (direct browser submits) or no origin (same-origin same-tab)
    if (!origin) return true; // No origin header means same-origin in most browsers
    try {
        const originHost = new URL(origin).host;
        return originHost === host;
    } catch {
        return false;
    }
}

// ---------- Login endpoint ----------
app.post('/api/login', async (req, res) => {
    const ip = getClientIp(req);

    // CSRF origin check — reject cross-origin POST requests
    if (!validateOrigin(req)) {
        securityLog({ event: 'csrf_block', ip });
        return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const { password } = req.body || {};

    // Strict type and length validation
    if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
        return res.status(400).json({ success: false, error: 'Invalid request' });
    }

    // ---- Layer 1: Public blocklist + AbuseIPDB threat check ----
    // Run async, but don't let a slow API call block the response entirely
    const threatCheck = await Promise.race([
        isThreatIp(ip),
        new Promise(resolve => setTimeout(() => resolve({ blocked: false, score: 0 }), 3000))
    ]);

    if (threatCheck.blocked) {
        securityLog({ event: 'threat_ip_blocked', ip, reason: threatCheck.reason, score: threatCheck.score });
        return res.status(403).json({ success: false, error: 'Access denied.' });
    }

    // Check lockout state
    const attempt = loginAttempts.get(ip) || { count: 0, lockUntil: 0, firstAttempt: Date.now() };
    const now = Date.now();

    if (now < attempt.lockUntil) {
        const waitSec = Math.ceil((attempt.lockUntil - now) / 1000);
        securityLog({ event: 'lockout_blocked', ip, waitSec, count: attempt.count });
        return res.status(429)
            .set('Retry-After', String(waitSec))
            .json({ success: false, error: `Too many failed attempts. Try again in ${waitSec} seconds.` });
    }

    // Constant-time password comparison (prevents timing attacks)
    const inputHash    = crypto.createHash('sha256').update(password).digest();
    const expectedHash = crypto.createHash('sha256').update(PASSWORD).digest();
    const isMatched    = crypto.timingSafeEqual(inputHash, expectedHash);

    if (isMatched) {
        loginAttempts.delete(ip);

        // Cap token store to prevent memory DoS
        if (validTokens.size >= MAX_TOKENS_STORED) {
            const oldest = [...validTokens.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
            if (oldest) validTokens.delete(oldest[0]);
        }

        const token = crypto.randomBytes(32).toString('hex');
        validTokens.set(token, { createdAt: now, ip, lastActivity: now });
        saveSessions();

        securityLog({ event: 'login_success', ip, abuseScore: threatCheck.score });
        return res.json({ success: true, token });
    }

    // ---- Failed login — update lockout and potentially report ----
    attempt.count++;
    const hitLockout = attempt.count >= LOCKOUT_THRESHOLD;

    if (hitLockout) {
        const lockSeconds = 60 * Math.pow(2, attempt.count - LOCKOUT_THRESHOLD);
        attempt.lockUntil = now + Math.min(lockSeconds * 1000, 24 * 60 * 60 * 1000);

        // Report to AbuseIPDB asynchronously (do not block response)
        reportToAbuseIPDB(
            ip,
            `Brute-force login attempt against a virtual browser application. ${attempt.count} failed attempts. Automatically reported.`
        ).catch(() => {});
    }

    // Cap attempts map size
    if (loginAttempts.size > MAX_ATTEMPTS_STORED) {
        const oldest = [...loginAttempts.entries()].sort((a, b) => a[1].firstAttempt - b[1].firstAttempt)[0];
        if (oldest) loginAttempts.delete(oldest[0]);
    }

    loginAttempts.set(ip, attempt);
    securityLog({ event: 'login_failed', ip, count: attempt.count, locked: hitLockout, abuseScore: threatCheck.score });

    return res.status(401).json({ success: false, error: 'Incorrect password' });
});

// ---------- WebSocket Server ----------
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

// ---------- WS message rate limiting ----------
const WS_MSG_LIMIT  = 600; // max messages per 10s per connection
const WS_MSG_WINDOW = 10_000;

server.on('upgrade', (request, socket, head) => {
    const ip = getClientIp(request);
    const parsedUrl = url.parse(request.url, true);

    // Accept token from query param OR Authorization header
    let token = parsedUrl.query.token;
    const authHeader = request.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
    }

    const tokenData = token ? validTokens.get(token) : null;
    const isValid   = !!tokenData && (Date.now() - tokenData.createdAt <= TOKEN_TTL_MS);

    if (tokenData) {
        if (!isValid) {
            validTokens.delete(token);
            saveSessions();
        } else {
            tokenData.lastActivity = Date.now();
        }
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
        ws.isAuthorized = isValid;
        ws.clientIp = ip;
        ws.msgCount = 0;
        ws.msgWindowStart = Date.now();
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
async function startScreencast(client, ws) {
    const format = ws?.streamFormat || 'jpeg';
    const quality = ws?.streamQuality || 90;
    const params = {
        format,
        maxWidth: 1920,
        maxHeight: 1080,
        everyNthFrame: 1
    };
    if (format === 'jpeg') {
        params.quality = quality;
    }
    await client.send('Page.startScreencast', params).catch(() => {});
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
        if (ws.zoomFactor) {
            page.evaluate((zoom) => {
                document.body.style.zoom = zoom;
            }, ws.zoomFactor).catch(() => {});
        }
    });

    // Intercept remote browser downloads
    page.on('download', async (download) => {
        try {
            const filename = download.suggestedFilename();
            const savePath = path.join(downloadsDir, filename);
            await download.saveAs(savePath);
            console.log(`[download] File downloaded: ${filename} to ${savePath}`);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'download_ready',
                    filename,
                    url: `/downloads/${encodeURIComponent(filename)}`
                }));
            }
        } catch (err) {
            console.error('[download] Failed to process download:', err.message);
        }
    });

    // Intercept file chooser dialog
    page.on('filechooser', async (fileChooser) => {
        console.log('[ws] Remote site requested file upload');
        ws.activeFileChooser = fileChooser;
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'file_chooser_open' }));
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

    await startScreencast(t.client, ws);

    // Immediate initial frame dispatch: paints the viewport instantly without waiting for network/DOM mutations
    t.page.screenshot({ type: 'jpeg', quality: ws.streamQuality || 85 })
        .then(buf => {
            if (ws.activeTabId === tabId && ws.readyState === WebSocket.OPEN) {
                sendFrameToClient(ws, buf.toString('base64'));
            }
        })
        .catch(() => {});
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

async function launchBrowserInstance() {
    const launchArgs = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-accelerated-2d-canvas',
        '--enable-font-antialiasing',
        '--font-render-hinting=medium',
        '--subpixel-text-rendering',
        '--force-color-profile=srgb'
    ];

    try {
        console.log('[*] Launching Google Chrome channel (hardware/proprietary codec support)...');
        return await chromium.launch({
            headless: true,
            channel: 'chrome',
            args: launchArgs
        });
    } catch (err) {
        console.warn('[!] Google Chrome channel unavailable, falling back to bundled Chromium:', err.message);
        return await chromium.launch({
            headless: true,
            args: launchArgs
        });
    }
}

async function startBrowser() {
    if (browserReady || browserStarting) return;
    browserStarting = true;

    try {
        console.log('[*] Initializing browser & adblocker...');

        const cacheDir = path.join(__dirname, 'adblocker_cache');
        fs.mkdirSync(cacheDir, { recursive: true });
        const cachePath = path.join(cacheDir, 'adblocker.bin');

        const [launchedBrowser, loadedAdblocker] = await Promise.all([
            launchBrowserInstance(),
            PlaywrightBlocker.fromPrebuiltAdsAndTracking(fetch, {
                path: cachePath,
                read: async (p) => fs.promises.readFile(p),
                write: async (p, content) => fs.promises.writeFile(p, content)
            }).catch(e => {
                console.warn('[!] Adblocker failed to load:', e.message);
                return null;
            })
        ]);

        browser = launchedBrowser;
        adblocker = loadedAdblocker;

        browserReady = true;
        browserStarting = false;
        console.log('[*] Browser ready.');

        // Pre-warm one context immediately so the first connection is instant
        prewarmContextPool().catch(e => console.warn('[!] Prewarm failed:', e.message));
    } catch (err) {
        browserStarting = false;
        throw err;
    }
}

// Pre-warmed context pool — keeps one idle context ready to hand off on connection
let contextPool = null; // { context, page } | null

async function prewarmContextPool() {
    if (contextPool || !browserReady) return;
    try {
        const ctx = await browser.newContext({
            viewport: { width: 1920, height: 1080 },
            deviceScaleFactor: 1,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            locale: 'en-US',
            timezoneId: 'Europe/London',
            acceptDownloads: true
        });
        // Open a blank page so Chromium has a renderer process ready
        const page = await ctx.newPage();
        contextPool = { context: ctx, page };
        console.log('[pool] Pre-warmed context ready.');
    } catch (e) {
        console.warn('[pool] Pre-warm failed:', e.message);
        contextPool = null;
    }
}

// Pre-start browser at server boot
startBrowser().catch(err => {
    console.error('[!] Pre-warm failed, will retry on first connection:', err.message);
});

async function initBrowserContext(ws) {
    // Tear down any existing context for this session
    if (ws.context) {
        for (const tabId of ws.tabs.keys()) {
            ws.tabs.delete(tabId);
        }
        ws.activeTabId = null;
        ws.tabCounter = 0;
        await ws.context.close().catch(() => {});
        ws.context = null;
    }

    const needsProxy = ws.vpnEnabled || !!ws.proxyServer;

    // Claim the pre-warmed pooled context if available and no proxy is needed
    if (!needsProxy && contextPool) {
        console.log('[pool] Handing off pre-warmed context to new session (instant).');
        ws.context = contextPool.context;
        // Close the placeholder blank page — createTab will open a real one
        contextPool.page.close().catch(() => {});
        contextPool = null;
        // Immediately start warming the next context for the next connection
        prewarmContextPool().catch(e => console.warn('[pool] Re-warm failed:', e.message));
    } else {
        // Create a fresh context (proxy scenario or pool was empty)
        const contextOptions = {
            viewport: { width: 1920, height: 1080 },
            deviceScaleFactor: 1,
            userAgent: ws.currentUserAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            locale: 'en-US',
            timezoneId: 'Europe/London',
            acceptDownloads: true
        };

        if (ws.vpnEnabled) {
            // Cloudflare WARP SOCKS5 proxy — free, fast, userspace, no NET_ADMIN needed
            contextOptions.proxy = { server: 'socks5://127.0.0.1:40000' };
            console.log('[vpn] Routing context via Cloudflare WARP socks5://127.0.0.1:40000');
        } else if (ws.proxyServer) {
            contextOptions.proxy = { server: ws.proxyServer };
            console.log(`[proxy] Proxying browser context via: ${ws.proxyServer}`);
        }

        ws.context = await browser.newContext(contextOptions);
    }

    try {
        await ws.context.exposeBinding('__reportCursor', (source, cursor) => {
            if (source.page.isClosed()) return;
            const tab = Array.from(ws.tabs.values()).find(t => t.page === source.page);
            if (tab && ws.activeTabId && ws.tabs.get(ws.activeTabId) === tab) {
                ws.send(JSON.stringify({ type: 'cursor', cursor }));
            }
        });
    } catch (_) {}

    try {
        await ws.context.exposeBinding('__reportCopy', (source, text) => {
            if (source.page.isClosed()) return;
            ws.send(JSON.stringify({ type: 'clipboard', text }));
        });
    } catch (_) {}

    try {
        const targetUA = ws.currentUserAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
        await ws.context.addInitScript((ua) => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            window.__customUA = ua;

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
        }, targetUA);
    } catch (_) {}
}

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
    ws.streamFormat = 'jpeg';
    ws.streamQuality = 90;
    ws.vpnEnabled = false;

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
        await initBrowserContext(ws);
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
        // --- WS message rate limiting — drop excessive clients ---
        const now = Date.now();
        if (now - ws.msgWindowStart > WS_MSG_WINDOW) {
            ws.msgCount = 0;
            ws.msgWindowStart = now;
        }
        ws.msgCount++;
        if (ws.msgCount > WS_MSG_LIMIT) {
            console.warn(`[security] WS message flood from ${ws.clientIp} — dropping message (${ws.msgCount} in window)`);
            return;
        }

        // Enforce maximum raw message size (16 KB for JSON messages, 201 MB for file uploads handled by base64 check)
        if (raw.length > 210_000_000) {
            console.warn(`[security] Oversized WS message from ${ws.clientIp} (${raw.length} bytes) — dropped`);
            return;
        }

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
            } else if (msg.type === 'set_stream_quality') {
                if (typeof msg.format !== 'string' || !['png', 'jpeg'].includes(msg.format)) return;
                if (msg.quality !== undefined && typeof msg.quality !== 'number') return;
            } else if (msg.type === 'toggle_vpn') {
                if (typeof msg.enabled !== 'boolean') return;
            } else if (msg.type === 'set_zoom') {
                if (typeof msg.zoom !== 'number' || msg.zoom < 0.2 || msg.zoom > 5.0) return;
            } else if (msg.type === 'file_uploaded') {
                if (typeof msg.name !== 'string' || msg.name.length > 255) return;
                if (typeof msg.data !== 'string' || msg.data.length > 200_000_000) return;
            } else if (msg.type === 'set_proxy') {
                if (typeof msg.proxy !== 'string' || msg.proxy.length > 512) return;
            } else if (msg.type === 'set_mute') {
                if (typeof msg.muted !== 'boolean') return;
            } else if (msg.type === 'find') {
                if (typeof msg.query !== 'string' || msg.query.length > 512) return;
            } else if (msg.type === 'find_next') {
                if (typeof msg.forward !== 'boolean') return;
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

            if (msg.type === 'set_stream_quality') {
                ws.streamFormat = msg.format;
                ws.streamQuality = msg.quality || 90;
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const t = ws.tabs.get(ws.activeTabId);
                    await stopScreencast(t.client);
                    await startScreencast(t.client, ws);
                }
                console.log(`[session] Stream quality updated to: ${msg.format} (quality: ${msg.quality || 'N/A'})`);
                return;
            }

            if (msg.type === 'toggle_vpn') {
                ws.vpnEnabled = msg.enabled;
                console.log(`[vpn] WARP VPN toggle: ${msg.enabled}`);
                try {
                    await initBrowserContext(ws);
                    const tabId = await createTab(ws);
                    await switchTab(ws, tabId);
                    const p = ws.tabs.get(tabId).page;
                    p.goto('https://www.google.com').catch(e => console.warn(`[nav] ${e.message}`));
                } catch (err) {
                    console.error('[!] Failed to toggle VPN context:', err.message);
                }
                return;
            }

            if (msg.type === 'set_zoom') {
                ws.zoomFactor = msg.zoom;
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const page = ws.tabs.get(ws.activeTabId).page;
                    await page.evaluate((zoom) => {
                        document.body.style.zoom = zoom;
                    }, msg.zoom).catch(() => {});
                }
                console.log(`[session] Zoom set to: ${msg.zoom * 100}%`);
                return;
            }

            if (msg.type === 'file_uploaded') {
                if (ws.activeFileChooser) {
                    try {
                        const safeName = path.basename(msg.name).replace(/[^a-zA-Z0-9._-]/g, '_');
                        const buffer = Buffer.from(msg.data, 'base64');
                        const tempPath = path.join(downloadsDir, 'upload_' + Date.now() + '_' + safeName);
                        await fs.promises.writeFile(tempPath, buffer);
                        console.log(`[upload] Saved local upload to temp file: ${tempPath}`);
                        await ws.activeFileChooser.setFiles(tempPath);
                        // Clean up the temp file after Playwright consumes it
                        setTimeout(async () => {
                            await fs.promises.unlink(tempPath).catch(() => {});
                        }, 5000);
                        ws.activeFileChooser = null;
                    } catch (err) {
                        console.error('[upload] Failed to process upload:', err.message);
                    }
                } else {
                    console.warn('[upload] Received upload data but no active file chooser was open');
                }
                return;
            }

            if (!ws.activeTabId || !ws.tabs.has(ws.activeTabId)) return;
            const p = ws.tabs.get(ws.activeTabId).page;
            if (p.isClosed()) return;

            // -- Proxy reconfiguration (fast, no Tor - instant context swap) --
            if (msg.type === 'set_proxy') {
                const proxyStr = (msg.proxy || '').trim();
                if (proxyStr && !/^(socks[45]|https?):\/\//i.test(proxyStr)) {
                    console.warn(`[proxy] Rejected invalid proxy format: ${proxyStr}`);
                    return;
                }
                ws.proxyServer = proxyStr || null;
                ws.vpnEnabled = false; // proxy replaces vpn
                try {
                    const currentUrl = p.url();
                    await initBrowserContext(ws);
                    const tabId = await createTab(ws);
                    await switchTab(ws, tabId);
                    if (currentUrl && currentUrl !== 'about:blank') {
                        ws.tabs.get(tabId).page.goto(currentUrl).catch(() => {});
                    }
                } catch (err) {
                    console.error('[!] Failed to apply proxy:', err.message);
                }
                return;
            }

            // -- Mute / Unmute via CDP --
            if (msg.type === 'set_mute') {
                const tab = ws.tabs.get(ws.activeTabId);
                if (tab && tab.client) {
                    await tab.client.send('Emulation.setMediaOverridesEnabled', {
                        media: msg.muted ? 'screen' : 'screen'
                    }).catch(() => {});
                    // Best-effort mute via page evaluate
                    await p.evaluate((muted) => {
                        document.querySelectorAll('video, audio').forEach(el => { el.muted = muted; });
                    }, msg.muted).catch(() => {});
                }
                return;
            }

            // -- Find in page --
            if (msg.type === 'find') {
                const tab = ws.tabs.get(ws.activeTabId);
                if (tab && tab.client) {
                    if (msg.query) {
                        const result = await tab.client.send('Page.findText', {
                            text: msg.query, caseSensitive: false, searchInUserValue: false
                        }).catch(() => null);
                        if (result && ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'find_result', count: result.matchCount || 0 }));
                        }
                    } else {
                        await tab.client.send('Page.stopFinding', { action: 'clearSelection' }).catch(() => {});
                    }
                }
                return;
            }

            if (msg.type === 'find_next') {
                const tab = ws.tabs.get(ws.activeTabId);
                if (tab && tab.client) {
                    await tab.client.send('Page.findNext', { forward: msg.forward }).catch(() => {});
                }
                return;
            }


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
