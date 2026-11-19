const express = require('express');
const { chromium } = require('playwright');
const { PlaywrightBlocker } = require('@ghostery/adblocker-playwright');
const WebSocket = require('ws');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const NODE_ENV = process.env.NODE_ENV || 'production';
const PASSWORD = process.env.PASSWORD || (NODE_ENV === 'test' ? 'test_secure_password_1234' : '');
const ALLOW_PRIVATE_NAV = process.env.ALLOW_PRIVATE_NAV !== '0';
const MAX_TABS_PER_SESSION = parseInt(process.env.MAX_TABS || '12', 10);
const MAX_WS_SESSIONS = parseInt(process.env.MAX_WS_SESSIONS || '8', 10);
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || String(16 * 1024 * 1024), 10); // 16 MB
const IDLE_TTL_MS = parseInt(process.env.IDLE_TTL_MS || String(4 * 60 * 60 * 1000), 10); // 4h idle
const TOKEN_TTL_MS = parseInt(process.env.TOKEN_TTL_MS || String(24 * 60 * 60 * 1000), 10); // 24h absolute
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const COOKIE_NAME = 'vb_session';
const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const MOBILE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';

// ---------- Startup Security Assertions ----------
if (!PASSWORD || PASSWORD === 'password123') {
    console.error('[FATAL] Refusing to start with missing or default PASSWORD. Set a strong PASSWORD env var (8+ chars, not password123).');
    process.exit(1);
}
if (PASSWORD.length < 8) {
    console.error('[FATAL] PASSWORD must be at least 8 characters. Exiting.');
    process.exit(1);
}

process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err.message, '\n', err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled rejection:', reason);
});

// ---------- Utility Functions ----------
function getClientIp(req) {
    if (TRUST_PROXY) {
        const xff = req.headers['x-forwarded-for'];
        const ip = xff ? xff.split(',')[0].trim() : req.socket.remoteAddress;
        return ip || 'unknown';
    }
    return req.socket.remoteAddress || 'unknown';
}

function getEffectiveHost(req) {
    if (TRUST_PROXY) {
        const xfh = req.headers['x-forwarded-host'];
        if (xfh) return xfh.split(',')[0].trim();
    }
    return req.headers.host || '';
}

function hashToken(token) {
    return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function parseCookies(header) {
    const out = {};
    if (!header) return out;
    for (const part of String(header).split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (k) {
            try {
                out[k] = decodeURIComponent(v);
            } catch {
                out[k] = v;
            }
        }
    }
    return out;
}

function extractRawToken(req) {
    const cookies = parseCookies(req.headers?.cookie || req.headers?.Cookie);
    if (cookies[COOKIE_NAME]) return cookies[COOKIE_NAME];

    const authHeader = req.headers?.authorization || '';
    if (authHeader.startsWith('Bearer ')) return authHeader.slice(7).trim();

    try {
        const u = new URL(req.url || '/', 'http://localhost');
        if (u.searchParams.get('token')) return u.searchParams.get('token');
    } catch (_) {}
    return null;
}

function isTokenValid(meta, now = Date.now()) {
    if (!meta) return false;
    if (now - meta.createdAt > TOKEN_TTL_MS) return false;
    if (now - (meta.lastActivity || meta.createdAt) > IDLE_TTL_MS) return false;
    return true;
}

function touchToken(meta) {
    if (meta) meta.lastActivity = Date.now();
}

function sessionCookie(token, req) {
    const maxAge = Math.floor(TOKEN_TTL_MS / 1000);
    const proto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0].trim();
    const secure = req.secure || proto === 'https' || process.env.FORCE_SECURE_COOKIE === '1';
    return `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

function clearSessionCookie(req) {
    const proto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0].trim();
    const secure = req.secure || proto === 'https' || process.env.FORCE_SECURE_COOKIE === '1';
    return `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure ? '; Secure' : ''}`;
}

function sanitizeDownloadName(name) {
    let base = path.basename(String(name || 'download'))
        .replace(/[^\w.\-()+ ]+/g, '_')
        .replace(/^[_.\s-]+|[_.\s-]+$/g, '')
        .trim();
    return base.slice(0, 180) || 'download';
}

function isPrivateOrBlockedHost(hostname) {
    if (!hostname) return true;
    const host = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return true;
    if (host === 'metadata.google.internal' || host.endsWith('.nip.io') || host.endsWith('.sslip.io')) return true;

    const plain = host.replace(/^::ffff:/, '');
    if (plain === '::1' || plain === '::' || plain === '0.0.0.0' || plain === '') return true;
    if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(plain)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(plain)) return true;
    if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(plain)) return true; // CGNAT
    if (/^(fc|fd|fe80)/i.test(plain)) return true; // IPv6 unique local & link-local
    return false;
}

function assertSafeNavigationUrl(rawUrl, allowPrivate = ALLOW_PRIVATE_NAV) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch {
        throw new Error('Invalid URL');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Only http/https navigation is allowed');
    }
    if (!allowPrivate && isPrivateOrBlockedHost(parsed.hostname)) {
        throw new Error('Navigation to private/internal addresses is blocked');
    }
    return parsed.toString();
}

function validateOrigin(req) {
    const origin = req.headers.origin || '';
    const referer = req.headers.referer || '';
    const host = getEffectiveHost(req);

    if (origin) {
        try {
            return new URL(origin).host.toLowerCase() === host.toLowerCase();
        } catch {
            return false;
        }
    }
    if (referer) {
        try {
            return new URL(referer).host.toLowerCase() === host.toLowerCase();
        } catch {
            return false;
        }
    }
    return process.env.ALLOW_EMPTY_ORIGIN === '1';
}

// ---------- Auth State & Persistence ----------
const validTokens = new Map();   // tokenHash -> { createdAt, ip, lastActivity }
const loginAttempts = new Map(); // ip -> { count, lockUntil, firstAttempt }
const globalRateMap = new Map(); // ip -> { requests, windowStart }
const activeSockets = new Set();

const LOCKOUT_THRESHOLD = 5;
const GLOBAL_REQ_LIMIT = 240;
const GLOBAL_REQ_WINDOW = 60_000;
const MAX_ATTEMPTS_STORED = 5_000;
const MAX_TOKENS_STORED = 500;

const dataRoot = path.join(__dirname, 'browser_data');
const SESSIONS_FILE = path.join(dataRoot, 'sessions.json');
const downloadsDir = path.join(dataRoot, 'downloads');
fs.mkdirSync(downloadsDir, { recursive: true });

function loadSessions() {
    try {
        if (!fs.existsSync(SESSIONS_FILE)) return;
        const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
        const data = JSON.parse(raw);
        const now = Date.now();
        if (!Array.isArray(data)) return;
        for (const item of data) {
            if (!item) continue;
            const key = item.tokenHash || (item.token ? hashToken(item.token) : null);
            if (!key || !item.createdAt) continue;
            const meta = {
                createdAt: item.createdAt,
                ip: item.ip || 'unknown',
                lastActivity: item.lastActivity || item.createdAt
            };
            if (isTokenValid(meta, now)) validTokens.set(key, meta);
        }
        console.log(`[auth] Restored ${validTokens.size} active sessions from disk.`);
    } catch (e) {
        console.warn('[auth] Could not load saved sessions:', e.message);
    }
}

function saveSessions() {
    try {
        const data = Array.from(validTokens.entries()).map(([tokenHash, meta]) => ({
            tokenHash,
            createdAt: meta.createdAt,
            ip: meta.ip,
            lastActivity: meta.lastActivity
        }));
        const tmp = SESSIONS_FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(data), 'utf8');
        fs.renameSync(tmp, SESSIONS_FILE);
    } catch (e) {
        console.warn('[auth] Could not save sessions:', e.message);
    }
}

loadSessions();

// Housekeeping interval
const housekeepingTimer = setInterval(() => {
    const now = Date.now();
    let cleaned = false;
    for (const [tokenHash, v] of validTokens) {
        if (!isTokenValid(v, now)) {
            validTokens.delete(tokenHash);
            cleaned = true;
        }
    }
    if (cleaned) saveSessions();

    for (const [ip, v] of loginAttempts) {
        if (v.lockUntil && now > v.lockUntil + 3_600_000) {
            loginAttempts.delete(ip);
        } else if (!v.lockUntil && now - v.firstAttempt > 3_600_000) {
            loginAttempts.delete(ip);
        }
    }

    for (const [ip, v] of globalRateMap) {
        if (now - v.windowStart > GLOBAL_REQ_WINDOW) globalRateMap.delete(ip);
    }

    fs.readdir(downloadsDir, (err, files) => {
        if (err || !files) return;
        const cutoff = now - (24 * 60 * 60 * 1000);
        files.forEach((file) => {
            const filePath = path.join(downloadsDir, file);
            fs.stat(filePath, (statErr, stats) => {
                if (!statErr && stats.isFile() && stats.mtimeMs < cutoff) {
                    fs.unlink(filePath, () => {});
                }
            });
        });
    });
}, 5 * 60 * 1000);
if (housekeepingTimer.unref) housekeepingTimer.unref();

// ---------- Security Logging & Threat Feeds ----------
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY || null;
const ABUSEIPDB_BLOCK_SCORE = parseInt(process.env.ABUSEIPDB_BLOCK_SCORE || '80', 10);
const securityLogPath = path.join(dataRoot, 'security.log');
const abuseScoreCache = new Map();
const SCORE_CACHE_TTL = 60 * 60 * 1000;

let publicBlocklist = new Set();
let blocklistLastUpdated = null;

const BLOCKLIST_FEEDS = [
    'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
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
                if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
                const ip = trimmed.split(/\s+/)[0];
                if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) newSet.add(ip);
            }
        } catch (e) {
            console.warn(`[blocklist] Failed to fetch ${feedUrl}: ${e.message}`);
        }
    }
    publicBlocklist = newSet;
    blocklistLastUpdated = new Date().toISOString();
    console.log(`[blocklist] Refreshed: ${publicBlocklist.size} blocked IPs from ${BLOCKLIST_FEEDS.length} feeds.`);
}

if (require.main === module && !process.env.SKIP_BLOCKLIST_REFRESH && process.env.NODE_ENV !== 'test') {
    refreshBlocklists().catch(() => {});
}
const blocklistTimer = setInterval(() => {
    if (process.env.NODE_ENV !== 'test') refreshBlocklists().catch(() => {});
}, 60 * 60 * 1000);
if (blocklistTimer.unref) blocklistTimer.unref();

function securityLog(event) {
    const entry = JSON.stringify({ ts: new Date().toISOString(), ...event }) + '\n';
    fs.appendFile(securityLogPath, entry, () => {});
    if (NODE_ENV !== 'production' || process.env.DEBUG_SECURITY === '1') {
        console.warn(`[security-log] ${JSON.stringify(event)}`);
    }
}

async function checkAbuseIPDB(ip) {
    if (!ABUSEIPDB_KEY || isPrivateOrBlockedHost(ip)) return null;
    const cached = abuseScoreCache.get(ip);
    if (cached && Date.now() - cached.fetchedAt < SCORE_CACHE_TTL) return cached;

    try {
        const cleanIp = ip.replace(/^::ffff:/, '');
        const res = await fetch(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(cleanIp)}&maxAgeInDays=30&verbose`,
            {
                headers: { Key: ABUSEIPDB_KEY, Accept: 'application/json' },
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

async function isThreatIp(ip) {
    const plain = ip.replace(/^::ffff:/, '');
    if (publicBlocklist.has(plain)) {
        return { blocked: true, reason: 'Public threat feed match', score: 100 };
    }
    const abuse = await checkAbuseIPDB(ip);
    if (abuse && abuse.score >= ABUSEIPDB_BLOCK_SCORE) {
        return {
            blocked: true,
            reason: `AbuseIPDB score ${abuse.score}/100`,
            score: abuse.score,
            isp: abuse.isp,
            country: abuse.countryCode
        };
    }
    return { blocked: false, score: abuse?.score ?? 0 };
}

// ---------- Express Middleware ----------
app.set('trust proxy', TRUST_PROXY ? 1 : false);
app.use(express.json({ limit: '64kb' }));

// Global Rate Limiter
app.use((req, res, next) => {
    const ip = getClientIp(req);
    const now = Date.now();
    const entry = globalRateMap.get(ip) || { requests: 0, windowStart: now };

    if (now - entry.windowStart > GLOBAL_REQ_WINDOW) {
        entry.requests = 0;
        entry.windowStart = now;
    }
    entry.requests++;

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

// Security Headers
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: blob: https://www.google.com https://icons.duckduckgo.com",
        "connect-src 'self' ws: wss:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ].join('; '));
    res.setHeader('Cache-Control', 'no-store');

    const proto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0].trim();
    if (req.secure || proto === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
});

// Static Assets
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
        else res.setHeader('Cache-Control', 'public, max-age=300');
    }
}));

function requireSession(req, res, next) {
    const raw = extractRawToken(req);
    if (!raw) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const meta = validTokens.get(hashToken(raw));
    if (!isTokenValid(meta)) {
        if (meta) {
            validTokens.delete(hashToken(raw));
            saveSessions();
        }
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    touchToken(meta);
    req.sessionToken = raw;
    req.sessionMeta = meta;
    next();
}

// Authenticated Downloads
app.use('/downloads', requireSession, express.static(downloadsDir, {
    dotfiles: 'deny',
    index: false,
    setHeaders: (res) => {
        res.setHeader('Content-Disposition', 'attachment');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'private, no-store');
    }
}));

// Download Management API (List & Delete)
app.get('/api/downloads', requireSession, (req, res) => {
    fs.readdir(downloadsDir, async (err, files) => {
        if (err || !files) return res.json({ files: [] });
        const list = [];
        for (const file of files) {
            try {
                const filePath = path.join(downloadsDir, file);
                const stats = await fs.promises.stat(filePath);
                if (stats.isFile()) {
                    const parts = file.split('_');
                    const originalName = parts.length > 1 ? parts.slice(1).join('_') : file;
                    list.push({
                        storedName: file,
                        filename: originalName,
                        size: stats.size,
                        createdAt: stats.birthtimeMs || stats.mtimeMs,
                        url: `/downloads/${encodeURIComponent(file)}`
                    });
                }
            } catch (_) {}
        }
        list.sort((a, b) => b.createdAt - a.createdAt);
        res.json({ files: list });
    });
});

app.delete('/api/downloads/:name', requireSession, async (req, res) => {
    try {
        const file = path.basename(req.params.name);
        const filePath = path.resolve(downloadsDir, file);
        if (!filePath.startsWith(path.resolve(downloadsDir) + path.sep)) {
            return res.status(400).json({ success: false, error: 'Invalid file path' });
        }
        await fs.promises.unlink(filePath);
        res.json({ success: true });
    } catch {
        res.status(500).json({ success: false, error: 'Failed to delete file' });
    }
});

// ---------- API Routes ----------
app.get('/healthz', (_req, res) => {
    if (!browserReady) {
        return res.status(503).json({
            ok: false,
            browserReady: false,
            browserStarting,
            activeSockets: activeSockets.size,
            sessions: validTokens.size
        });
    }
    res.json({
        ok: true,
        browserReady: true,
        activeSockets: activeSockets.size,
        sessions: validTokens.size
    });
});

app.get('/api/security/log', requireSession, (req, res) => {
    try {
        if (!fs.existsSync(securityLogPath)) return res.json({ count: 0, events: [] });
        const raw = fs.readFileSync(securityLogPath, 'utf8');
        const lines = raw.trim().split('\n').filter(Boolean);
        const entries = lines.slice(-200).map((l) => {
            try { return JSON.parse(l); } catch { return null; }
        }).filter(Boolean);
        res.json({ count: entries.length, events: entries.reverse() });
    } catch {
        res.json({ count: 0, events: [] });
    }
});

app.get('/api/security/blocklist', requireSession, (_req, res) => {
    res.json({
        totalBlocked: publicBlocklist.size,
        lastUpdated: blocklistLastUpdated,
        feeds: BLOCKLIST_FEEDS,
        abuseipdbEnabled: !!ABUSEIPDB_KEY,
        blockScoreThreshold: ABUSEIPDB_BLOCK_SCORE
    });
});

app.post('/api/login', async (req, res) => {
    const ip = getClientIp(req);

    if (!validateOrigin(req)) {
        securityLog({ event: 'csrf_block', ip });
        return res.status(403).json({ success: false, error: 'Cross-origin request forbidden' });
    }

    const { password } = req.body || {};
    if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
        return res.status(400).json({ success: false, error: 'Password required' });
    }

    const threatCheck = await Promise.race([
        isThreatIp(ip),
        new Promise((resolve) => setTimeout(() => resolve({ blocked: false, score: 0 }), 3000))
    ]);

    if (threatCheck.blocked) {
        securityLog({ event: 'threat_ip_blocked', ip, reason: threatCheck.reason, score: threatCheck.score });
        return res.status(403).json({ success: false, error: 'Access denied.' });
    }

    const attempt = loginAttempts.get(ip) || { count: 0, lockUntil: 0, firstAttempt: Date.now() };
    const now = Date.now();

    if (now < attempt.lockUntil) {
        const waitSec = Math.ceil((attempt.lockUntil - now) / 1000);
        securityLog({ event: 'lockout_blocked', ip, waitSec, count: attempt.count });
        return res.status(429)
            .set('Retry-After', String(waitSec))
            .json({ success: false, error: `Too many failed attempts. Try again in ${waitSec} seconds.` });
    }

    const inputHash = crypto.createHash('sha256').update(password).digest();
    const expectedHash = crypto.createHash('sha256').update(PASSWORD).digest();
    const isMatched = inputHash.length === expectedHash.length && crypto.timingSafeEqual(inputHash, expectedHash);

    if (isMatched) {
        loginAttempts.delete(ip);

        if (validTokens.size >= MAX_TOKENS_STORED) {
            const oldest = [...validTokens.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
            if (oldest) validTokens.delete(oldest[0]);
        }

        const token = crypto.randomBytes(32).toString('hex');
        validTokens.set(hashToken(token), { createdAt: now, ip, lastActivity: now });
        saveSessions();
        res.setHeader('Set-Cookie', sessionCookie(token, req));
        securityLog({ event: 'login_success', ip, abuseScore: threatCheck.score });
        return res.json({ success: true, token });
    }

    attempt.count++;
    const hitLockout = attempt.count >= LOCKOUT_THRESHOLD;
    if (hitLockout) {
        const lockSeconds = 60 * Math.pow(2, attempt.count - LOCKOUT_THRESHOLD);
        attempt.lockUntil = now + Math.min(lockSeconds * 1000, 24 * 60 * 60 * 1000);
        reportToAbuseIPDB(
            ip,
            `Brute-force login attempt against virtual browser application. ${attempt.count} failed attempts.`
        ).catch(() => {});
    }

    if (loginAttempts.size > MAX_ATTEMPTS_STORED) {
        const oldest = [...loginAttempts.entries()].sort((a, b) => a[1].firstAttempt - b[1].firstAttempt)[0];
        if (oldest) loginAttempts.delete(oldest[0]);
    }

    loginAttempts.set(ip, attempt);
    securityLog({ event: 'login_failed', ip, count: attempt.count, locked: hitLockout, abuseScore: threatCheck.score });
    return res.status(401).json({ success: false, error: 'Incorrect password' });
});

app.post('/api/logout', (req, res) => {
    if (!validateOrigin(req)) {
        return res.status(403).json({ success: false, error: 'Cross-origin request forbidden' });
    }
    const raw = extractRawToken(req);
    if (raw) {
        validTokens.delete(hashToken(raw));
        saveSessions();
    }
    res.setHeader('Set-Cookie', clearSessionCookie(req));
    res.json({ success: true });
});

app.get('/api/session', (req, res) => {
    const raw = extractRawToken(req);
    if (!raw) return res.status(401).json({ authenticated: false });
    const meta = validTokens.get(hashToken(raw));
    if (!isTokenValid(meta)) return res.status(401).json({ authenticated: false });
    touchToken(meta);
    res.json({ authenticated: true });
});

app.use((err, req, res, _next) => {
    console.error('[express-error]', err.message);
    res.status(err.status || 500).json({ success: false, error: err.message || 'Internal server error' });
});

// ---------- Browser Engine Management ----------
let browser = null;
let adblocker = null;
let browserStarting = false;
let browserReady = false;

async function launchBrowserInstance() {
    const launchArgs = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-accelerated-2d-canvas',
        '--enable-font-antialiasing',
        '--font-render-hinting=medium',
        '--force-color-profile=srgb',
        '--disable-blink-features=AutomationControlled',
        '--force-webrtc-ip-handling-policy=default_public_interface_only',
        '--disable-features=IsolateOrigins,site-per-process'
    ];

    try {
        console.log('[*] Launching Google Chrome channel with anti-detection flags...');
        const inst = await chromium.launch({ headless: true, channel: 'chrome', args: launchArgs });
        inst.on('disconnected', () => {
            console.warn('[!] Browser process disconnected or crashed.');
            browserReady = false;
            browser = null;
            contextPool = null;
        });
        return inst;
    } catch (err) {
        console.warn('[!] Chrome channel unavailable, falling back to Chromium:', err.message);
        const inst = await chromium.launch({ headless: true, args: launchArgs });
        inst.on('disconnected', () => {
            console.warn('[!] Browser process disconnected or crashed.');
            browserReady = false;
            browser = null;
            contextPool = null;
        });
        return inst;
    }
}

async function startBrowser() {
    if (browserReady || browserStarting) return;
    browserStarting = true;

    try {
        console.log('[*] Initializing browser engine...');
        browser = await launchBrowserInstance();
        browserReady = true;
        browserStarting = false;
        console.log('[*] Browser engine ready.');

        prewarmContextPool().catch(() => {});

        const cacheDir = path.join(__dirname, 'adblocker_cache');
        fs.mkdirSync(cacheDir, { recursive: true });
        const cachePath = path.join(cacheDir, 'adblocker.bin');

        PlaywrightBlocker.fromPrebuiltAdsAndTracking(fetch, {
            path: cachePath,
            read: async (p) => fs.promises.readFile(p),
            write: async (p, content) => fs.promises.writeFile(p, content)
        }).then((loadedBlocker) => {
            adblocker = loadedBlocker;
            console.log('[*] Adblocker rules loaded and ready.');
        }).catch((e) => {
            console.warn('[!] Adblocker background load warning:', e.message);
        });
    } catch (err) {
        browserStarting = false;
        browserReady = false;
        browser = null;
        throw err;
    }
}

let contextPool = null;

async function prewarmContextPool() {
    if (contextPool || !browserReady || !browser) return;
    try {
        const ctx = await browser.newContext({
            viewport: { width: 1920, height: 1080 },
            deviceScaleFactor: 1,
            userAgent: DEFAULT_UA,
            locale: 'en-US',
            timezoneId: 'Europe/London',
            acceptDownloads: true
        });

        await attachContextBindings(ctx);

        const page = await ctx.newPage();
        const client = await ctx.newCDPSession(page);
        await Promise.all([
            client.send('Page.enable'),
            client.send('DOM.enable'),
            client.send('Overlay.enable').catch(() => {})
        ]);

        page.goto('https://www.google.com').catch(() => {});
        contextPool = { context: ctx, page, client };
        console.log('[pool] Pre-warmed context ready.');
    } catch (e) {
        console.warn('[pool] Pre-warm failed:', e.message);
        contextPool = null;
    }
}

async function attachContextBindings(ctx) {
    try {
        await ctx.exposeBinding('__reportCursor', (source, cursor) => {
            const ws = ctx._ownerWs;
            if (!ws || source.page.isClosed()) return;
            const tab = Array.from(ws.tabs.values()).find((t) => t.page === source.page);
            if (tab && ws.activeTabId && ws.tabs.get(ws.activeTabId) === tab && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'cursor', cursor }));
            }
        });
    } catch (_) {}

    try {
        await ctx.exposeBinding('__reportCopy', (source, text) => {
            const ws = ctx._ownerWs;
            if (!ws || source.page.isClosed() || ws.readyState !== WebSocket.OPEN) return;
            ws.send(JSON.stringify({ type: 'clipboard', text: String(text || '').slice(0, 100_000) }));
        });
    } catch (_) {}

    try {
        await ctx.exposeBinding('__reportAudioState', (source, isPlaying) => {
            const ws = ctx._ownerWs;
            if (!ws || source.page.isClosed()) return;
            const tabEntry = Array.from(ws.tabs.entries()).find(([_, t]) => t.page === source.page);
            if (tabEntry) {
                const [tabId, tab] = tabEntry;
                tab.isPlayingAudio = !!isPlaying;
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'tab_audio_state', tabId, isPlayingAudio: tab.isPlayingAudio }));
                }
            }
        });
    } catch (_) {}

    try {
        await ctx.addInitScript(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

            document.addEventListener('mouseover', (e) => {
                try {
                    const c = window.getComputedStyle(e.target).cursor;
                    if (window.__reportCursor) window.__reportCursor(c);
                } catch (_) {}
            }, { passive: true, capture: true });

            document.addEventListener('copy', () => {
                try {
                    const selected = window.getSelection().toString();
                    if (selected && window.__reportCopy) window.__reportCopy(selected);
                } catch (_) {}
            }, { passive: true, capture: true });

            document.addEventListener('play', (e) => {
                if (['VIDEO', 'AUDIO'].includes(e.target?.tagName) && window.__reportAudioState) {
                    window.__reportAudioState(true);
                }
            }, { capture: true, passive: true });

            document.addEventListener('pause', (e) => {
                if (['VIDEO', 'AUDIO'].includes(e.target?.tagName) && window.__reportAudioState) {
                    const anyPlaying = Array.from(document.querySelectorAll('video, audio')).some(el => !el.paused && !el.ended);
                    window.__reportAudioState(anyPlaying);
                }
            }, { capture: true, passive: true });
        });
    } catch (_) {}
}

if (require.main === module) {
    startBrowser().catch((err) => {
        console.error('[!] Initial browser start failed, will retry on connection:', err.message);
    });
}

// ---------- WebSocket Server & Connection Management ----------
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true, maxPayload: Math.max(MAX_UPLOAD_BYTES * 2, 4 * 1024 * 1024) });

const WS_MSG_LIMIT = 1000;
const WS_MSG_WINDOW = 10_000;

server.on('upgrade', (request, socket, head) => {
    const ip = getClientIp(request);

    if (!validateOrigin(request)) {
        securityLog({ event: 'cswsh_blocked', ip, origin: request.headers.origin || 'none' });
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
    }

    const rawToken = extractRawToken(request);
    const tokenHash = rawToken ? hashToken(rawToken) : null;
    const tokenData = tokenHash ? validTokens.get(tokenHash) : null;
    const isValid = isTokenValid(tokenData);

    if (!isValid) {
        if (tokenHash && tokenData) {
            validTokens.delete(tokenHash);
            saveSessions();
        }
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
    }

    if (activeSockets.size >= MAX_WS_SESSIONS) {
        socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
    }

    touchToken(tokenData);

    wss.handleUpgrade(request, socket, head, (ws) => {
        ws.isAuthorized = true;
        ws.clientIp = ip;
        ws.tokenHash = tokenHash;
        ws.msgCount = 0;
        ws.msgWindowStart = Date.now();
        wss.emit('connection', ws, request);
    });
});

function sendFrameToClient(ws, data) {
    if (ws.readyState !== WebSocket.OPEN) return;

    if (ws.ackTimeout) {
        clearTimeout(ws.ackTimeout);
        ws.ackTimeout = null;
    }

    if (!ws.frameInFlight) {
        ws.frameInFlight = true;
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'base64');
        ws.send(buffer);

        ws.ackTimeout = setTimeout(() => {
            ws.frameInFlight = false;
            if (ws.lastFrameData) {
                const nextData = ws.lastFrameData;
                ws.lastFrameData = null;
                sendFrameToClient(ws, nextData);
            }
        }, 1200);
    } else {
        ws.lastFrameData = data;
        ws.droppedFrames = (ws.droppedFrames || 0) + 1;
    }
}

function sendTabState(ws) {
    if (ws.readyState !== WebSocket.OPEN) return;
    const tabList = Array.from(ws.tabs.entries()).map(([id, t]) => ({
        id,
        title: t.title,
        url: t.url,
        favicon: t.favicon,
        isActive: id === ws.activeTabId,
        isPlayingAudio: !!t.isPlayingAudio
    }));
    ws.send(JSON.stringify({ type: 'tab_state', tabs: tabList }));
}

async function startScreencast(client, ws) {
    const format = ws?.streamFormat || 'jpeg';
    const quality = ws?.streamQuality || 80;
    const everyNthFrame = ws?.frameInFlight ? 2 : 1;
    const params = {
        format,
        maxWidth: ws?.viewportWidth || 1920,
        maxHeight: ws?.viewportHeight || 1080,
        everyNthFrame
    };
    if (format === 'jpeg') params.quality = quality;
    await client.send('Page.startScreencast', params).catch(() => {});
}

async function stopScreencast(client) {
    await client.send('Page.stopScreencast').catch(() => {});
}

async function renderErrorPage(page, url, errorMessage) {
    if (page.isClosed()) return;
    const safeUrl = escapeHtml(url);
    const safeErr = escapeHtml(errorMessage);
    const errorHtml = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Navigation Error</title>
<style>
body{background:#0b1120;color:#f8fafc;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;padding:20px;box-sizing:border-box}
.container{max-width:520px;width:100%;text-align:center;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:36px;box-shadow:0 15px 35px rgba(0,0,0,0.6)}
h1{font-size:22px;margin:0 0 12px;color:#ef4444;font-weight:600}
p{font-size:14px;color:#94a3b8;line-height:1.6;word-break:break-word}
.url{font-family:monospace;background:#0f172a;padding:8px 12px;border-radius:6px;margin:16px 0;border:1px solid rgba(255,255,255,0.06);font-size:13px}
.btn{background:#3b82f6;color:#fff;border:none;border-radius:8px;padding:10px 24px;font-size:14px;font-weight:600;cursor:pointer;margin-top:16px;transition:background 0.2s}
.btn:hover{background:#2563eb}
</style></head>
<body><div class="container">
<h1>Navigation Failed</h1>
<p>The isolated virtual browser was unable to load the requested page:</p>
<div class="url">${safeUrl}</div>
<p><strong>Reason:</strong> ${safeErr}</p>
<button class="btn" id="retry">Retry Navigation</button>
</div>
<script>
document.getElementById('retry').addEventListener('click', function () {
  location.href = ${JSON.stringify(String(url || ''))};
});
</script>
</body></html>`;
    await page.setContent(errorHtml).catch(() => {});
}

async function createTab(ws, existingPage = null, existingClient = null) {
    if (ws.tabs.size >= MAX_TABS_PER_SESSION) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'error', error: `Tab limit reached (${MAX_TABS_PER_SESSION}). Close an existing tab first.` }));
        }
        if (existingPage && !existingPage.isClosed()) {
            await existingPage.close().catch(() => {});
        }
        return null;
    }

    const tabId = 'tab_' + (++ws.tabCounter);
    const page = existingPage || await ws.context.newPage();

    const targetUA = ws.currentUserAgent || DEFAULT_UA;
    await page.addInitScript((ua) => {
        try {
            Object.defineProperty(navigator, 'userAgent', { get: () => ua });
        } catch (_) {}
    }, targetUA).catch(() => {});

    if (ws.allowPrivateNav === false) {
        await page.route('**/*', (route) => {
            try {
                const reqUrl = new URL(route.request().url());
                if (isPrivateOrBlockedHost(reqUrl.hostname)) {
                    return route.abort();
                }
            } catch {
                return route.abort();
            }
            route.continue();
        }).catch(() => {});
    }

    if (adblocker && ws.adblockerEnabled) {
        await adblocker.enableBlockingInPage(page).catch(() => {});
    }

    // Remote Console & Error Monitoring
    page.on('console', (cMsg) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'console_event',
                tabId,
                level: cMsg.type(),
                text: cMsg.text(),
                location: cMsg.location()
            }));
        }
    });

    page.on('pageerror', (pErr) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'console_event',
                tabId,
                level: 'error',
                text: pErr.message
            }));
        }
    });

    // Handle Page Dialogs (alerts, confirms, prompts)
    page.on('dialog', async (dialog) => {
        page._pendingDialog = dialog;
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'dialog',
                tabId,
                message: dialog.message(),
                dialogType: dialog.type(),
                defaultValue: dialog.defaultValue()
            }));
        } else {
            await dialog.dismiss().catch(() => {});
        }
    });

    page.on('domcontentloaded', () => {
        if (tabId === ws.activeTabId && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'loading_state', loading: false }));
        }
        if (ws.zoomFactor) {
            page.evaluate((zoom) => {
                if (document.body) document.body.style.zoom = zoom;
            }, ws.zoomFactor).catch(() => {});
        }
        if (ws.isMuted) {
            page.evaluate(() => {
                document.querySelectorAll('video, audio').forEach((el) => { el.muted = true; });
            }).catch(() => {});
        }
    });

    page.on('download', async (download) => {
        try {
            const rawName = download.suggestedFilename();
            const safeName = sanitizeDownloadName(rawName);
            const fileId = crypto.randomBytes(6).toString('hex');
            const storedName = `${fileId}_${safeName}`;
            const resolved = path.resolve(downloadsDir, storedName);

            if (!resolved.startsWith(path.resolve(downloadsDir) + path.sep)) {
                throw new Error('Invalid download path');
            }

            await download.saveAs(resolved);
            console.log(`[download] Saved: ${safeName} (${storedName})`);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'download_ready',
                    filename: safeName,
                    url: `/downloads/${encodeURIComponent(storedName)}`
                }));
            }
        } catch (err) {
            console.error('[download] Failed:', err.message);
        }
    });

    page.on('filechooser', async (fileChooser) => {
        ws.activeFileChooser = fileChooser;
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'file_chooser_open',
                isMultiple: fileChooser.isMultiple()
            }));
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

    page.on('response', (res) => {
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'network_event',
                    tabId,
                    status: res.status(),
                    url: res.url(),
                    method: res.request().method(),
                    resourceType: res.request().resourceType()
                }));
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

    page.on('close', () => {
        if (ws.tabs.has(tabId)) {
            closeTab(ws, tabId).catch(() => {});
        }
    });

    const client = existingClient || await page.context().newCDPSession(page);
    if (!existingClient) {
        await Promise.all([
            client.send('Page.enable'),
            client.send('DOM.enable'),
            client.send('Overlay.enable').catch(() => {})
        ]);
    }

    const currentUrl = page.url() || 'about:blank';
    ws.tabs.set(tabId, {
        page,
        client,
        title: currentUrl.includes('google') ? 'Google' : 'New Tab',
        url: currentUrl,
        favicon: '',
        isPlayingAudio: false,
        searchId: null,
        searchCount: 0,
        searchIndex: 0
    });

    page.on('framenavigated', (frame) => {
        if (frame !== page.mainFrame()) return;
        const t = ws.tabs.get(tabId);
        if (!t || page.isClosed()) return;
        t.url = frame.url();

        page.title()
            .then((title) => { if (t) t.title = title || 'New Tab'; })
            .catch(() => {})
            .then(() => page.evaluate(() => {
                const el = document.querySelector("link[rel~='icon'], link[rel='shortcut icon']");
                return el ? el.href : '';
            }))
            .then((fav) => {
                if (!t) return;
                try {
                    if (!fav) { t.favicon = ''; return; }
                    const host = new URL(fav, t.url).hostname;
                    t.favicon = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=32`;
                } catch {
                    t.favicon = '';
                }
            })
            .catch(() => {})
            .finally(() => {
                sendTabState(ws);
                if (tabId === ws.activeTabId && ws.readyState === WebSocket.OPEN) {
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

    if (ws.ackTimeout) {
        clearTimeout(ws.ackTimeout);
        ws.ackTimeout = null;
    }
    ws.frameInFlight = false;
    ws.lastFrameData = null;

    sendTabState(ws);
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'url_changed', url: t.url }));
    }

    if (ws.zoomFactor && !t.page.isClosed()) {
        t.page.evaluate((zoom) => {
            if (document.body) document.body.style.zoom = zoom;
        }, ws.zoomFactor).catch(() => {});
    }

    if (ws.isMuted && !t.page.isClosed()) {
        t.page.evaluate(() => {
            document.querySelectorAll('video, audio').forEach((el) => { el.muted = true; });
        }).catch(() => {});
    }

    await startScreencast(t.client, ws);

    t.page.screenshot({ type: 'jpeg', quality: Math.min(ws.streamQuality || 80, 85) })
        .then((buf) => {
            if (ws.activeTabId === tabId && ws.readyState === WebSocket.OPEN) {
                sendFrameToClient(ws, buf);
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
            const nextTabId = Array.from(ws.tabs.keys()).pop();
            await switchTab(ws, nextTabId);
        } else {
            ws.activeTabId = null;
            sendTabState(ws);
            const newId = await createTab(ws);
            if (newId) {
                await switchTab(ws, newId);
                ws.tabs.get(newId).page.goto('https://www.google.com').catch((e) => console.warn(`[nav] ${e.message}`));
            }
        }
    } else {
        sendTabState(ws);
    }
}

async function initBrowserContext(ws) {
    if (ws.context) {
        for (const tabId of [...ws.tabs.keys()]) ws.tabs.delete(tabId);
        ws.activeTabId = null;
        await ws.context.close().catch(() => {});
        ws.context = null;
    }

    const needsProxy = ws.vpnEnabled || !!ws.proxyServer;
    let prewarmed = null;
    const ua = ws.currentUserAgent || DEFAULT_UA;
    const isMobile = ws.isMobileUa === true;

    if (!ws.viewportWidth || !ws.viewportHeight) {
        ws.viewportWidth = isMobile ? 390 : 1920;
        ws.viewportHeight = isMobile ? 844 : 1080;
    }

    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'viewport_dimensions',
            width: ws.viewportWidth,
            height: ws.viewportHeight,
            isMobile
        }));
    }

    if (!needsProxy && !isMobile && ua === DEFAULT_UA && contextPool) {
        console.log('[pool] Handing off pre-warmed context.');
        ws.context = contextPool.context;
        ws.context._ownerWs = ws;
        prewarmed = { page: contextPool.page, client: contextPool.client };
        contextPool = null;
        prewarmContextPool().catch((e) => console.warn('[pool] Re-warm failed:', e.message));
    } else {
        const contextOptions = {
            viewport: { width: ws.viewportWidth, height: ws.viewportHeight },
            deviceScaleFactor: isMobile ? 3 : 1,
            userAgent: ua,
            locale: 'en-US',
            timezoneId: 'Europe/London',
            acceptDownloads: true,
            isMobile,
            hasTouch: isMobile
        };

        if (ws.vpnEnabled) {
            contextOptions.proxy = { server: 'socks5://127.0.0.1:40000' };
            console.log('[vpn] Routing via Cloudflare WARP socks5://127.0.0.1:40000');
        } else if (ws.proxyServer) {
            contextOptions.proxy = { server: ws.proxyServer };
            console.log(`[proxy] Proxying via: ${ws.proxyServer}`);
        }

        ws.context = await browser.newContext(contextOptions);
        ws.context._ownerWs = ws;
        await attachContextBindings(ws.context);
    }

    ws.context.on('page', async (newPage) => {
        try {
            console.log('[popup] Handling new window/popup');
            const newTabId = await createTab(ws, newPage);
            if (newTabId) {
                await switchTab(ws, newTabId);
            }
        } catch (e) {
            console.warn('[popup] Failed to handle popup page:', e.message);
        }
    });

    return prewarmed;
}

async function recreateSessionBrowser(ws, navigateTo) {
    const target = navigateTo || 'https://www.google.com';
    await initBrowserContext(ws);
    const tabId = await createTab(ws);
    if (!tabId) return;
    await switchTab(ws, tabId);
    const page = ws.tabs.get(tabId).page;
    try {
        const safe = assertSafeNavigationUrl(target, ws.allowPrivateNav);
        await page.goto(safe).catch((e) => renderErrorPage(page, safe, e.message));
    } catch (e) {
        await renderErrorPage(page, target, e.message);
    }
}

function buildSearchUrl(query, engine) {
    const q = encodeURIComponent(query);
    switch (engine) {
        case 'duckduckgo':
            return `https://duckduckgo.com/?q=${q}`;
        case 'brave':
            return `https://search.brave.com/search?q=${q}`;
        case 'bing':
            return `https://www.bing.com/search?q=${q}`;
        case 'ecosia':
            return `https://www.ecosia.org/search?q=${q}`;
        case 'google':
        default:
            return `https://www.google.com/search?q=${q}`;
    }
}

wss.on('connection', async (ws) => {
    if (!ws.isAuthorized) {
        ws.close(4001, 'Unauthorized');
        return;
    }

    if (activeSockets.size >= MAX_WS_SESSIONS) {
        ws.close(1013, 'Too many active sessions');
        return;
    }

    activeSockets.add(ws);
    console.log(`[+] Client connected (${activeSockets.size} active sessions)`);

    ws.frameInFlight = false;
    ws.lastFrameData = null;
    ws.tabs = new Map();
    ws.activeTabId = null;
    ws.tabCounter = 0;
    ws.adblockerEnabled = true;
    ws.currentUserAgent = DEFAULT_UA;
    ws.isMobileUa = false;
    ws.streamFormat = 'jpeg';
    ws.streamQuality = 80;
    ws.vpnEnabled = false;
    ws.isMuted = false;
    ws.zoomFactor = 1;
    ws.viewportWidth = 1920;
    ws.viewportHeight = 1080;
    ws.searchEngine = 'google';
    ws.allowPrivateNav = ALLOW_PRIVATE_NAV;

    let waited = 0;
    while (browserStarting && waited < 60_000) {
        await new Promise((r) => setTimeout(r, 250));
        waited += 250;
    }

    if (!browserReady || !browser) {
        try {
            await startBrowser();
        } catch (err) {
            console.error('[!] startBrowser failed:', err.message);
            ws.close(1011, 'Browser engine failed to start');
            return;
        }
    }

    let prewarmed = null;
    try {
        prewarmed = await initBrowserContext(ws);
    } catch (err) {
        console.error('[!] Failed to create browser context:', err.message);
        ws.close(1011, 'Failed to initialize session');
        return;
    }

    const tabId = await createTab(ws, prewarmed?.page, prewarmed?.client);
    if (tabId) {
        await switchTab(ws, tabId);
        if (!prewarmed) {
            ws.tabs.get(tabId).page.goto('https://www.google.com').catch((e) => console.warn(`[nav] ${e.message}`));
        }
    }

    ws.on('message', async (raw) => {
        const now = Date.now();
        if (now - ws.msgWindowStart > WS_MSG_WINDOW) {
            ws.msgCount = 0;
            ws.msgWindowStart = now;
        }
        ws.msgCount++;
        if (ws.msgCount > WS_MSG_LIMIT) return;

        if (raw.length > MAX_UPLOAD_BYTES * 2 + 64_000) {
            console.warn(`[security] Oversized WS message from ${ws.clientIp} (${raw.length} bytes)`);
            return;
        }

        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        try {
            if (!msg || typeof msg.type !== 'string') return;

            const vw = ws.viewportWidth || 1920;
            const vh = ws.viewportHeight || 1080;

            if (msg.type === 'mousemove' || msg.type === 'mousedown' || msg.type === 'mouseup') {
                if (typeof msg.x !== 'number' || typeof msg.y !== 'number') return;
                msg.x = Math.max(0, Math.min(vw, Math.round(msg.x)));
                msg.y = Math.max(0, Math.min(vh, Math.round(msg.y)));
                if (msg.button && !['left', 'middle', 'right'].includes(msg.button)) return;
            } else if (msg.type === 'wheel') {
                if (typeof msg.deltaX !== 'number' || typeof msg.deltaY !== 'number') return;
                msg.deltaX = Math.max(-5000, Math.min(5000, msg.deltaX));
                msg.deltaY = Math.max(-5000, Math.min(5000, msg.deltaY));
            } else if (msg.type === 'keydown' || msg.type === 'keyup') {
                if (typeof msg.key !== 'string' || msg.key.length > 50) return;
                if (msg.modifiers && (!Array.isArray(msg.modifiers) || msg.modifiers.some((m) => typeof m !== 'string' || m.length > 20))) return;
            } else if (msg.type === 'goto' || msg.type === 'new_tab') {
                if (msg.url && (typeof msg.url !== 'string' || msg.url.length > 2048)) return;
            } else if (msg.type === 'type') {
                if (typeof msg.text !== 'string' || msg.text.length > 30000) return;
            } else if (msg.type === 'switch_tab' || msg.type === 'close_tab' || msg.type === 'duplicate_tab' || msg.type === 'close_other_tabs' || msg.type === 'reload_tab') {
                if (typeof msg.tabId !== 'string' || !/^tab_\d+$/.test(msg.tabId)) return;
            } else if (msg.type === 'set_viewport') {
                if (typeof msg.width !== 'number' || typeof msg.height !== 'number') return;
                msg.width = Math.max(320, Math.min(3840, Math.round(msg.width)));
                msg.height = Math.max(240, Math.min(2160, Math.round(msg.height)));
            } else if (msg.type === 'toggle_adblocker' || msg.type === 'toggle_vpn' || msg.type === 'toggle_private_nav') {
                if (typeof msg.enabled !== 'boolean') return;
            } else if (msg.type === 'set_mute') {
                if (typeof msg.muted !== 'boolean') return;
            } else if (msg.type === 'mute_tab') {
                if (typeof msg.tabId !== 'string' || typeof msg.muted !== 'boolean') return;
            } else if (msg.type === 'set_useragent') {
                if (typeof msg.userAgent !== 'string' || msg.userAgent.length > 512) return;
            } else if (msg.type === 'set_stream_quality') {
                if (typeof msg.format !== 'string' || !['png', 'jpeg'].includes(msg.format)) return;
                if (msg.quality !== undefined && (typeof msg.quality !== 'number' || msg.quality < 10 || msg.quality > 100)) return;
            } else if (msg.type === 'set_zoom') {
                if (typeof msg.zoom !== 'number' || msg.zoom < 0.2 || msg.zoom > 5.0) return;
            } else if (msg.type === 'file_uploaded') {
                if (typeof msg.name !== 'string' || msg.name.length > 255) return;
                if (typeof msg.data !== 'string') return;
            } else if (msg.type === 'files_uploaded') {
                if (!Array.isArray(msg.files) || msg.files.length > 20) return;
            } else if (msg.type === 'set_proxy') {
                if (typeof msg.proxy !== 'string' || msg.proxy.length > 512) return;
            } else if (msg.type === 'set_search_engine') {
                if (typeof msg.engine !== 'string' || !['google', 'duckduckgo', 'brave', 'bing', 'ecosia'].includes(msg.engine)) return;
            } else if (msg.type === 'find') {
                if (typeof msg.query !== 'string' || msg.query.length > 512) return;
            } else if (msg.type === 'find_next') {
                if (typeof msg.forward !== 'boolean') return;
            } else if (msg.type === 'dialog_response') {
                if (typeof msg.accept !== 'boolean') return;
            }
        } catch {
            return;
        }

        if (ws.tokenHash) {
            const meta = validTokens.get(ws.tokenHash);
            if (!isTokenValid(meta)) {
                ws.close(4001, 'Session expired');
                return;
            }
            touchToken(meta);
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

            if (msg.type === 'set_viewport') {
                ws.viewportWidth = msg.width;
                ws.viewportHeight = msg.height;
                if (ws.context) {
                    for (const tab of ws.tabs.values()) {
                        if (!tab.page.isClosed()) {
                            await tab.page.setViewportSize({ width: msg.width, height: msg.height }).catch(() => {});
                        }
                    }
                }
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        type: 'viewport_dimensions',
                        width: ws.viewportWidth,
                        height: ws.viewportHeight,
                        isMobile: ws.isMobileUa === true
                    }));
                }
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const t = ws.tabs.get(ws.activeTabId);
                    await stopScreencast(t.client);
                    await startScreencast(t.client, ws);
                    t.page.screenshot({ type: 'jpeg', quality: Math.min(ws.streamQuality || 80, 85) })
                        .then((buf) => sendFrameToClient(ws, buf)).catch(() => {});
                }
                return;
            }

            if (msg.type === 'new_tab') {
                const id = await createTab(ws);
                if (!id) return;
                await switchTab(ws, id);
                const p = ws.tabs.get(id).page;
                let target = msg.url || 'https://www.google.com';
                try {
                    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
                    target = assertSafeNavigationUrl(target, ws.allowPrivateNav);
                    p.goto(target).catch((e) => renderErrorPage(p, target, e.message));
                } catch (e) {
                    renderErrorPage(p, msg.url || target, e.message);
                }
                return;
            }

            if (msg.type === 'duplicate_tab') {
                if (!ws.tabs.has(msg.tabId)) return;
                const srcTab = ws.tabs.get(msg.tabId);
                const newId = await createTab(ws);
                if (!newId) return;
                await switchTab(ws, newId);
                const p = ws.tabs.get(newId).page;
                const target = srcTab.url || 'https://www.google.com';
                try {
                    const safe = assertSafeNavigationUrl(target, ws.allowPrivateNav);
                    p.goto(safe).catch((e) => renderErrorPage(p, safe, e.message));
                } catch (e) {
                    renderErrorPage(p, target, e.message);
                }
                return;
            }

            if (msg.type === 'close_other_tabs') {
                for (const id of Array.from(ws.tabs.keys())) {
                    if (id !== msg.tabId) {
                        await closeTab(ws, id);
                    }
                }
                return;
            }

            if (msg.type === 'reload_tab') {
                if (ws.tabs.has(msg.tabId)) {
                    ws.tabs.get(msg.tabId).page.reload().catch(() => {});
                }
                return;
            }

            if (msg.type === 'mute_tab') {
                if (ws.tabs.has(msg.tabId)) {
                    const p = ws.tabs.get(msg.tabId).page;
                    await p.evaluate((muted) => {
                        document.querySelectorAll('video, audio').forEach((el) => { el.muted = muted; });
                    }, !!msg.muted).catch(() => {});
                }
                return;
            }

            if (msg.type === 'switch_tab') { await switchTab(ws, msg.tabId); return; }
            if (msg.type === 'close_tab') { await closeTab(ws, msg.tabId); return; }

            if (msg.type === 'set_search_engine') {
                ws.searchEngine = msg.engine;
                return;
            }

            if (msg.type === 'clear_session') {
                if (ws.context) {
                    await ws.context.clearCookies().catch(() => {});
                    for (const tab of ws.tabs.values()) tab.page.reload().catch(() => {});
                }
                return;
            }

            if (msg.type === 'get_cookies') {
                if (ws.context) {
                    const cookies = await ws.context.cookies().catch(() => []);
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'cookies_list', cookies }));
                    }
                }
                return;
            }

            if (msg.type === 'clear_cookies') {
                if (ws.context) {
                    if (msg.domain) {
                        const all = await ws.context.cookies().catch(() => []);
                        const filtered = all.filter(c => c.domain.includes(msg.domain));
                        // Playwright clearCookies takes name/domain filters
                        for (const c of filtered) {
                            await ws.context.clearCookies({ name: c.name, domain: c.domain }).catch(() => {});
                        }
                    } else {
                        await ws.context.clearCookies().catch(() => {});
                    }
                    if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                        ws.tabs.get(ws.activeTabId).page.reload().catch(() => {});
                    }
                }
                return;
            }

            if (msg.type === 'capture_screenshot') {
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const p = ws.tabs.get(ws.activeTabId).page;
                    try {
                        const buf = await p.screenshot({ fullPage: !!msg.fullPage, type: 'png' });
                        const fileId = crypto.randomBytes(6).toString('hex');
                        const filename = `screenshot_${Date.now()}.png`;
                        const storedName = `${fileId}_${filename}`;
                        const resolved = path.resolve(downloadsDir, storedName);
                        await fs.promises.writeFile(resolved, buf);

                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                type: 'download_ready',
                                filename,
                                url: `/downloads/${encodeURIComponent(storedName)}`
                            }));
                            ws.send(JSON.stringify({
                                type: 'screenshot_taken',
                                filename,
                                data: buf.toString('base64')
                            }));
                        }
                    } catch (e) {
                        console.warn('[screenshot] Error:', e.message);
                    }
                }
                return;
            }

            if (msg.type === 'export_pdf') {
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const p = ws.tabs.get(ws.activeTabId).page;
                    try {
                        const buf = await p.pdf({ format: 'A4', printBackground: true });
                        const fileId = crypto.randomBytes(6).toString('hex');
                        const filename = `document_${Date.now()}.pdf`;
                        const storedName = `${fileId}_${filename}`;
                        const resolved = path.resolve(downloadsDir, storedName);
                        await fs.promises.writeFile(resolved, buf);

                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                type: 'download_ready',
                                filename,
                                url: `/downloads/${encodeURIComponent(storedName)}`
                            }));
                        }
                    } catch (e) {
                        console.warn('[pdf] Error:', e.message);
                    }
                }
                return;
            }

            if (msg.type === 'toggle_adblocker') {
                ws.adblockerEnabled = !!msg.enabled;
                if (adblocker) {
                    for (const tab of ws.tabs.values()) {
                        if (msg.enabled) await adblocker.enableBlockingInPage(tab.page).catch(() => {});
                        else await adblocker.disableBlockingInPage(tab.page).catch(() => {});
                    }
                }
                return;
            }

            if (msg.type === 'toggle_private_nav') {
                ws.allowPrivateNav = !!msg.enabled;
                return;
            }

            if (msg.type === 'set_useragent') {
                const profiles = { desktop: DEFAULT_UA, mobile: MOBILE_UA };
                const key = msg.userAgent;
                const targetUA = profiles[key] || key;
                ws.currentUserAgent = targetUA;
                ws.isMobileUa = key === 'mobile' || /iPhone|Android|Mobile/i.test(targetUA);
                ws.viewportWidth = ws.isMobileUa ? 390 : 1920;
                ws.viewportHeight = ws.isMobileUa ? 844 : 1080;
                const currentUrl = (ws.activeTabId && ws.tabs.get(ws.activeTabId)?.url) || 'https://www.google.com';
                await recreateSessionBrowser(ws, currentUrl);
                return;
            }

            if (msg.type === 'set_stream_quality') {
                ws.streamFormat = msg.format;
                ws.streamQuality = typeof msg.quality === 'number' ? msg.quality : 80;
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const t = ws.tabs.get(ws.activeTabId);
                    await stopScreencast(t.client);
                    await startScreencast(t.client, ws);
                }
                return;
            }

            if (msg.type === 'toggle_vpn') {
                ws.vpnEnabled = !!msg.enabled;
                ws.proxyServer = null;
                try {
                    await recreateSessionBrowser(ws, 'https://www.google.com');
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
                        if (document.body) document.body.style.zoom = zoom;
                    }, msg.zoom).catch(() => {});
                }
                return;
            }

            if (msg.type === 'file_uploaded') {
                if (!ws.activeFileChooser) return;
                try {
                    const safeName = sanitizeDownloadName(msg.name);
                    const buffer = Buffer.from(msg.data, 'base64');
                    if (buffer.length > MAX_UPLOAD_BYTES) return;
                    const tempPath = path.join(downloadsDir, `upload_${Date.now()}_${safeName}`);
                    const resolved = path.resolve(tempPath);
                    if (!resolved.startsWith(path.resolve(downloadsDir) + path.sep)) return;
                    await fs.promises.writeFile(resolved, buffer);
                    await ws.activeFileChooser.setFiles(resolved);
                    setTimeout(() => fs.promises.unlink(resolved).catch(() => {}), 5000);
                    ws.activeFileChooser = null;
                } catch (err) {
                    console.error('[upload] Failed:', err.message);
                }
                return;
            }

            if (msg.type === 'files_uploaded') {
                if (!ws.activeFileChooser || !Array.isArray(msg.files)) return;
                try {
                    const filePaths = [];
                    for (const f of msg.files) {
                        const safeName = sanitizeDownloadName(f.name);
                        const buffer = Buffer.from(f.data, 'base64');
                        if (buffer.length > MAX_UPLOAD_BYTES) continue;
                        const tempPath = path.join(downloadsDir, `upload_${Date.now()}_${safeName}`);
                        const resolved = path.resolve(tempPath);
                        if (!resolved.startsWith(path.resolve(downloadsDir) + path.sep)) continue;
                        await fs.promises.writeFile(resolved, buffer);
                        filePaths.push(resolved);
                    }
                    if (filePaths.length > 0) {
                        await ws.activeFileChooser.setFiles(filePaths);
                        setTimeout(() => {
                            filePaths.forEach(p => fs.promises.unlink(p).catch(() => {}));
                        }, 5000);
                    }
                    ws.activeFileChooser = null;
                } catch (err) {
                    console.error('[upload-multi] Failed:', err.message);
                }
                return;
            }

            if (msg.type === 'file_chooser_cancel') {
                ws.activeFileChooser = null;
                return;
            }

            if (msg.type === 'dialog_response') {
                if (ws.activeTabId && ws.tabs.has(ws.activeTabId)) {
                    const page = ws.tabs.get(ws.activeTabId).page;
                    if (page._pendingDialog) {
                        const d = page._pendingDialog;
                        page._pendingDialog = null;
                        if (msg.accept) {
                            await d.accept(msg.promptText ? String(msg.promptText).slice(0, 1000) : undefined).catch(() => {});
                        } else {
                            await d.dismiss().catch(() => {});
                        }
                    }
                }
                return;
            }

            if (!ws.activeTabId || !ws.tabs.has(ws.activeTabId)) return;
            const p = ws.tabs.get(ws.activeTabId).page;
            if (p.isClosed()) return;

            if (msg.type === 'set_proxy') {
                const proxyStr = (msg.proxy || '').trim();
                if (proxyStr && !/^(socks[45]|https?):\/\//i.test(proxyStr)) {
                    console.warn(`[proxy] Rejected invalid proxy format: ${proxyStr}`);
                    return;
                }
                ws.proxyServer = proxyStr || null;
                ws.vpnEnabled = false;
                try {
                    const currentUrl = p.url();
                    await recreateSessionBrowser(ws, currentUrl && currentUrl !== 'about:blank' ? currentUrl : 'https://www.google.com');
                } catch (err) {
                    console.error('[!] Failed to apply proxy:', err.message);
                }
                return;
            }

            if (msg.type === 'set_mute') {
                ws.isMuted = !!msg.muted;
                await p.evaluate((muted) => {
                    document.querySelectorAll('video, audio').forEach((el) => { el.muted = muted; });
                }, ws.isMuted).catch(() => {});
                return;
            }

            if (msg.type === 'find') {
                const tab = ws.tabs.get(ws.activeTabId);
                if (!tab?.client) return;
                try {
                    if (tab.searchId) {
                        await tab.client.send('DOM.discardSearchResults', { searchId: tab.searchId }).catch(() => {});
                        tab.searchId = null;
                    }
                    if (msg.query) {
                        const result = await tab.client.send('DOM.performSearch', {
                            query: msg.query,
                            includeUserAgentShadowDOM: true
                        });
                        tab.searchId = result.searchId;
                        tab.searchCount = result.resultCount || 0;
                        tab.searchIndex = 0;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'find_result', count: tab.searchCount }));
                        }
                        if (tab.searchCount > 0) {
                            const matches = await tab.client.send('DOM.getSearchResults', {
                                searchId: result.searchId,
                                fromIndex: 0,
                                toIndex: 1
                            });
                            if (matches.nodeIds?.[0]) {
                                await tab.client.send('DOM.scrollIntoViewIfNeeded', { nodeId: matches.nodeIds[0] }).catch(() => {});
                                await tab.client.send('DOM.highlightNode', {
                                    nodeId: matches.nodeIds[0],
                                    highlightConfig: {
                                        borderColor: { r: 59, g: 130, b: 246, a: 1 },
                                        contentColor: { r: 59, g: 130, b: 246, a: 0.3 }
                                    }
                                }).catch(() => {});
                            }
                        }
                    } else if (ws.readyState === WebSocket.OPEN) {
                        tab.searchCount = 0;
                        tab.searchIndex = 0;
                        ws.send(JSON.stringify({ type: 'find_result', count: 0 }));
                    }
                } catch (err) {
                    console.warn('[find]', err.message);
                }
                return;
            }

            if (msg.type === 'find_next') {
                const tab = ws.tabs.get(ws.activeTabId);
                if (!tab?.client || !tab.searchId) return;
                try {
                    const n = tab.searchCount || 0;
                    if (n <= 0) return;
                    tab.searchIndex = typeof tab.searchIndex === 'number' ? tab.searchIndex : 0;
                    tab.searchIndex = msg.forward
                        ? (tab.searchIndex + 1) % n
                        : (tab.searchIndex - 1 + n) % n;
                    const matches = await tab.client.send('DOM.getSearchResults', {
                        searchId: tab.searchId,
                        fromIndex: tab.searchIndex,
                        toIndex: tab.searchIndex + 1
                    });
                    if (matches.nodeIds?.[0]) {
                        await tab.client.send('DOM.scrollIntoViewIfNeeded', { nodeId: matches.nodeIds[0] }).catch(() => {});
                        await tab.client.send('DOM.highlightNode', {
                            nodeId: matches.nodeIds[0],
                            highlightConfig: {
                                borderColor: { r: 59, g: 130, b: 246, a: 1 },
                                contentColor: { r: 59, g: 130, b: 246, a: 0.3 }
                            }
                        }).catch(() => {});
                    }
                } catch (err) {
                    console.warn('[find_next]', err.message);
                }
                return;
            }

            switch (msg.type) {
                case 'mousemove':
                    p.mouse.move(msg.x, msg.y).catch(() => {});
                    break;
                case 'mousedown':
                    p.mouse.move(msg.x, msg.y).catch(() => {});
                    p.mouse.down({ button: msg.button || 'left' }).catch(() => {});
                    break;
                case 'mouseup':
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
                    let isAutoprepended = false;
                    if (!/^https?:\/\//i.test(target)) {
                        const looksLikeIp = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/.test(target);
                        const looksLikeDomain = looksLikeIp
                            || /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/.test(target);

                        if (looksLikeDomain) {
                            target = 'https://' + target;
                            isAutoprepended = true;
                        } else {
                            target = buildSearchUrl(target, msg.searchEngine || ws.searchEngine);
                        }
                    }

                    try {
                        target = assertSafeNavigationUrl(target, ws.allowPrivateNav);
                    } catch (e) {
                        await renderErrorPage(p, msg.url, e.message);
                        break;
                    }

                    const activePage = p;
                    activePage.goto(target).catch(async (e) => {
                        console.warn(`[nav] ${e.message}`);
                        if (isAutoprepended && target.startsWith('https://')) {
                            try {
                                const fallbackUrl = assertSafeNavigationUrl(target.replace(/^https:/, 'http:'), ws.allowPrivateNav);
                                await activePage.goto(fallbackUrl).catch(async (err) => {
                                    await renderErrorPage(activePage, target, err.message);
                                });
                            } catch (err) {
                                await renderErrorPage(activePage, target, err.message);
                            }
                        } else {
                            await renderErrorPage(activePage, target, e.message);
                        }
                    });
                    break;
                }
                case 'type':
                    p.keyboard.insertText(msg.text).catch(() => {});
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
        activeSockets.delete(ws);
        console.log(`[-] Client disconnected (${activeSockets.size} active sessions)`);
        if (ws.ackTimeout) {
            clearTimeout(ws.ackTimeout);
            ws.ackTimeout = null;
        }
        if (ws.context) {
            await ws.context.close().catch(() => {});
            ws.context = null;
        }
    });

    ws.on('error', (err) => {
        console.error('[!] WebSocket error:', err.message);
    });
});

if (require.main === module) {
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`[*] MSuite-Browser listening on 0.0.0.0:${PORT}`);
    });
}

module.exports = {
    app,
    server,
    wss,
    startBrowser,
    getClientIp,
    getEffectiveHost,
    hashToken,
    escapeHtml,
    parseCookies,
    extractRawToken,
    isTokenValid,
    touchToken,
    sessionCookie,
    clearSessionCookie,
    sanitizeDownloadName,
    isPrivateOrBlockedHost,
    assertSafeNavigationUrl,
    validateOrigin,
    buildSearchUrl,
    validTokens,
    loginAttempts,
    globalRateMap,
    activeSockets,
    PASSWORD
};
