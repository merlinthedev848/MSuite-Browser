const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const WebSocket = require('ws');

process.env.NODE_ENV = 'test';
process.env.PASSWORD = 'test_secure_password_1234';
process.env.ALLOW_PRIVATE_NAV = '0';
process.env.ALLOW_EMPTY_ORIGIN = '0';

const { app, server, validTokens, loginAttempts, hashToken, sessionCookie } = require('../server.js');

let testServer;
let baseUrl;
let hostHeader;

test.before(async () => {
    await new Promise((resolve) => {
        testServer = server.listen(0, '127.0.0.1', () => {
            const addr = testServer.address();
            baseUrl = `http://127.0.0.1:${addr.port}`;
            hostHeader = `127.0.0.1:${addr.port}`;
            resolve();
        });
    });
});

test.after(async () => {
    if (testServer) {
        await new Promise((resolve) => testServer.close(resolve));
    }
});

test('Healthcheck: GET /healthz returns valid JSON status', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 503); // Browser engine not running in headless unit test
    const json = await res.json();
    assert.equal(typeof json.ok, 'boolean');
    assert.equal(typeof json.sessions, 'number');
});

test('Authentication: POST /api/login rejects cross-origin requests', async () => {
    const res = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Origin': 'https://evil-attacker.site',
            'Host': hostHeader
        },
        body: JSON.stringify({ password: 'test_secure_password_1234' })
    });
    assert.equal(res.status, 403);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.match(json.error, /Cross-origin/);
});

test('Authentication: POST /api/login rejects empty/invalid passwords', async () => {
    const res = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Origin': baseUrl,
            'Host': hostHeader
        },
        body: JSON.stringify({ password: '' })
    });
    assert.equal(res.status, 400);
    const json = await res.json();
    assert.equal(json.success, false);
});

test('Authentication: POST /api/login rejects incorrect passwords', async () => {
    loginAttempts.clear();
    const res = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Origin': baseUrl,
            'Host': hostHeader
        },
        body: JSON.stringify({ password: 'wrong_password_xyz' })
    });
    assert.equal(res.status, 401);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error, 'Incorrect password');
});

test('Authentication: POST /api/login succeeds with correct password and sets cookie', async () => {
    loginAttempts.clear();
    const res = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Origin': baseUrl,
            'Host': hostHeader
        },
        body: JSON.stringify({ password: 'test_secure_password_1234' })
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(json.token);

    const setCookie = res.headers.get('set-cookie');
    assert.ok(setCookie);
    assert.match(setCookie, /vb_session=/);
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Lax/i);
});

test('Session Verification: GET /api/session validates session state', async () => {
    // Unauthenticated
    const resUnauth = await fetch(`${baseUrl}/api/session`);
    assert.equal(resUnauth.status, 401);

    // Authenticated with valid token
    const testToken = 'valid_test_token_999888';
    validTokens.set(hashToken(testToken), {
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: '127.0.0.1'
    });

    const resAuth = await fetch(`${baseUrl}/api/session`, {
        headers: {
            'Cookie': `vb_session=${testToken}`
        }
    });
    assert.equal(resAuth.status, 200);
    const json = await resAuth.json();
    assert.equal(json.authenticated, true);
});

test('Session Logout: POST /api/logout clears session token and cookie', async () => {
    const testToken = 'logout_test_token_123';
    const testHash = hashToken(testToken);
    validTokens.set(testHash, {
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: '127.0.0.1'
    });

    const res = await fetch(`${baseUrl}/api/logout`, {
        method: 'POST',
        headers: {
            'Origin': baseUrl,
            'Host': hostHeader,
            'Cookie': `vb_session=${testToken}`
        }
    });
    assert.equal(res.status, 200);
    assert.equal(validTokens.has(testHash), false);
    const setCookie = res.headers.get('set-cookie');
    assert.match(setCookie, /Max-Age=0/);
});

test('Protected Endpoints: Reject unauthenticated requests', async () => {
    const resSec = await fetch(`${baseUrl}/api/security/blocklist`);
    assert.equal(resSec.status, 401);

    const resLogs = await fetch(`${baseUrl}/api/security/log`);
    assert.equal(resLogs.status, 401);

    const resDown = await fetch(`${baseUrl}/downloads/nonexistent.pdf`);
    assert.equal(resDown.status, 401);

    const resApiDown = await fetch(`${baseUrl}/api/downloads`);
    assert.equal(resApiDown.status, 401);
});

test('Download API: GET /api/downloads returns file list when authenticated', async () => {
    const testToken = 'dl_test_token_789';
    validTokens.set(hashToken(testToken), {
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: '127.0.0.1'
    });

    const res = await fetch(`${baseUrl}/api/downloads`, {
        headers: {
            'Cookie': `vb_session=${testToken}`
        }
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(Array.isArray(json.files), true);
});

test('WebSocket Upgrade: Rejects unauthenticated connections and CSWSH attacks', async () => {
    const wsUrl = baseUrl.replace(/^http/, 'ws');

    // 1. Unauthenticated WS Upgrade
    await new Promise((resolve) => {
        const client = new WebSocket(wsUrl, {
            headers: {
                'Origin': baseUrl,
                'Host': hostHeader
            }
        });
        client.on('unexpected-response', (_req, res) => {
            assert.equal(res.statusCode, 401);
            resolve();
        });
        client.on('error', () => resolve());
    });

    // 2. Cross-Site WebSocket Hijacking (CSWSH) Attempt
    const testToken = 'ws_security_test_token_456';
    validTokens.set(hashToken(testToken), {
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: '127.0.0.1'
    });

    await new Promise((resolve) => {
        const client = new WebSocket(wsUrl, {
            headers: {
                'Origin': 'https://evil-hacker.com',
                'Host': hostHeader,
                'Cookie': `vb_session=${testToken}`
            }
        });
        client.on('unexpected-response', (_req, res) => {
            assert.equal(res.statusCode, 403);
            resolve();
        });
        client.on('error', () => resolve());
    });
});
