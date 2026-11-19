const test = require('node:test');
const assert = require('node:assert/strict');

// Set test environment before requiring server
process.env.NODE_ENV = 'test';
process.env.PASSWORD = 'test_secure_password_1234';
process.env.ALLOW_PRIVATE_NAV = '0';
process.env.ALLOW_EMPTY_ORIGIN = '0';

const serverModule = require('../server.js');
const {
    hashToken,
    escapeHtml,
    parseCookies,
    sessionCookie,
    clearSessionCookie,
    sanitizeDownloadName,
    isPrivateOrBlockedHost,
    assertSafeNavigationUrl,
    validateOrigin,
    buildSearchUrl,
    isTokenValid
} = serverModule;

test('Security & Hashing: hashToken is deterministic and uses sha256', () => {
    const token = 'sample_test_token_abcdef123456';
    const hash1 = hashToken(token);
    const hash2 = hashToken(token);
    assert.equal(hash1, hash2);
    assert.equal(hash1.length, 64);
    assert.match(hash1, /^[0-9a-f]{64}$/);
});

test('XSS Mitigation: escapeHtml sanitizes special HTML characters', () => {
    const malicious = '<script>alert("XSS & attack")</script>\'test\'';
    const escaped = escapeHtml(malicious);
    assert.equal(escaped.includes('<script>'), false);
    assert.equal(escaped.includes('</script>'), false);
    assert.equal(escaped.includes('&lt;script&gt;'), true);
    assert.equal(escaped.includes('&amp;'), true);
    assert.equal(escaped.includes('&quot;'), true);
    assert.equal(escaped.includes('&#39;'), true);
});

test('Cookie Parsing: parseCookies correctly handles various header formats', () => {
    assert.deepEqual(parseCookies(''), {});
    assert.deepEqual(parseCookies(null), {});

    const header = 'vb_session=abc123xyz; other_cookie=hello%20world; empty=; trailing=ok;';
    const parsed = parseCookies(header);
    assert.equal(parsed.vb_session, 'abc123xyz');
    assert.equal(parsed.other_cookie, 'hello world');
    assert.equal(parsed.trailing, 'ok');
});

test('Session Cookie Generation: flags and max-age', () => {
    const mockReqHttp = { headers: {}, secure: false };
    const cookieHttp = sessionCookie('my_token_value', mockReqHttp);
    assert.match(cookieHttp, /^vb_session=my_token_value; HttpOnly; SameSite=Lax; Path=\/; Max-Age=\d+/);
    assert.equal(cookieHttp.includes('; Secure'), false);

    const mockReqHttps = { headers: { 'x-forwarded-proto': 'https' }, secure: false };
    const cookieHttps = sessionCookie('my_token_value', mockReqHttps);
    assert.equal(cookieHttps.includes('; Secure'), true);

    const clearCookie = clearSessionCookie(mockReqHttps);
    assert.match(clearCookie, /^vb_session=; HttpOnly; SameSite=Lax; Path=\/; Max-Age=0; Secure/);
});

test('Path Traversal Prevention: sanitizeDownloadName protects filesystem', () => {
    assert.equal(sanitizeDownloadName('../../../../etc/passwd'), 'passwd');
    assert.equal(sanitizeDownloadName('..\\..\\windows\\system32\\cmd.exe'), 'cmd.exe');
    assert.equal(sanitizeDownloadName('normal-file_name (1).pdf'), 'normal-file_name (1).pdf');
    assert.equal(sanitizeDownloadName(''), 'download');
    assert.equal(sanitizeDownloadName('!@#$%^&*<>:"/\\|?*'), 'download');
});

test('SSRF Protection: isPrivateOrBlockedHost rejects RFC1918, loopbacks, and metadata', () => {
    // Standard loopback and zero
    assert.equal(isPrivateOrBlockedHost('localhost'), true);
    assert.equal(isPrivateOrBlockedHost('foo.localhost'), true);
    assert.equal(isPrivateOrBlockedHost('printer.local'), true);
    assert.equal(isPrivateOrBlockedHost('service.internal'), true);
    assert.equal(isPrivateOrBlockedHost('127.0.0.1'), true);
    assert.equal(isPrivateOrBlockedHost('127.1.2.3'), true);
    assert.equal(isPrivateOrBlockedHost('0.0.0.0'), true);

    // RFC1918 Private Ranges
    assert.equal(isPrivateOrBlockedHost('10.0.0.1'), true);
    assert.equal(isPrivateOrBlockedHost('10.254.254.254'), true);
    assert.equal(isPrivateOrBlockedHost('172.16.0.1'), true);
    assert.equal(isPrivateOrBlockedHost('172.31.255.255'), true);
    assert.equal(isPrivateOrBlockedHost('192.168.0.1'), true);
    assert.equal(isPrivateOrBlockedHost('192.168.1.100'), true);

    // Cloud Provider Metadata & Link Local
    assert.equal(isPrivateOrBlockedHost('169.254.169.254'), true);
    assert.equal(isPrivateOrBlockedHost('metadata.google.internal'), true);

    // CGNAT
    assert.equal(isPrivateOrBlockedHost('100.64.0.1'), true);
    assert.equal(isPrivateOrBlockedHost('100.127.255.255'), true);

    // IPv6
    assert.equal(isPrivateOrBlockedHost('::1'), true);
    assert.equal(isPrivateOrBlockedHost('::'), true);
    assert.equal(isPrivateOrBlockedHost('fe80::1'), true);
    assert.equal(isPrivateOrBlockedHost('fc00::1'), true);
    assert.equal(isPrivateOrBlockedHost('fd12:3456:789a::1'), true);

    // DNS Rebinding wildcards
    assert.equal(isPrivateOrBlockedHost('127.0.0.1.nip.io'), true);
    assert.equal(isPrivateOrBlockedHost('test.sslip.io'), true);

    // Public Internet Hosts (Allowed)
    assert.equal(isPrivateOrBlockedHost('google.com'), false);
    assert.equal(isPrivateOrBlockedHost('github.com'), false);
    assert.equal(isPrivateOrBlockedHost('8.8.8.8'), false);
    assert.equal(isPrivateOrBlockedHost('1.1.1.1'), false);
});

test('Navigation Guard: assertSafeNavigationUrl strictly enforces protocol and boundaries', () => {
    // Valid public URLs
    assert.equal(assertSafeNavigationUrl('https://google.com/search?q=test'), 'https://google.com/search?q=test');
    assert.equal(assertSafeNavigationUrl('http://example.org/path'), 'http://example.org/path');

    // Blocked Protocols
    assert.throws(() => assertSafeNavigationUrl('javascript:alert(1)'), /Only http\/https navigation is allowed/);
    assert.throws(() => assertSafeNavigationUrl('file:///etc/passwd'), /Only http\/https navigation is allowed/);
    assert.throws(() => assertSafeNavigationUrl('data:text/html,<h1>test</h1>'), /Only http\/https navigation is allowed/);
    assert.throws(() => assertSafeNavigationUrl('blob:http://example.com/uuid'), /Only http\/https navigation is allowed/);
    assert.throws(() => assertSafeNavigationUrl('not a url'), /Invalid URL/);

    // Blocked Private/Internal Hosts when allowPrivate is false
    assert.throws(() => assertSafeNavigationUrl('http://127.0.0.1:8080/admin', false), /blocked/);
    assert.throws(() => assertSafeNavigationUrl('http://169.254.169.254/latest/meta-data/', false), /blocked/);
    assert.throws(() => assertSafeNavigationUrl('http://localhost:3000', false), /blocked/);
});

test('VPN / Intranet Access: assertSafeNavigationUrl permits internal LAN IPs when enabled', () => {
    assert.equal(assertSafeNavigationUrl('http://10.0.0.185:8080/', true), 'http://10.0.0.185:8080/');
    assert.equal(assertSafeNavigationUrl('http://192.168.1.1:8443/login', true), 'http://192.168.1.1:8443/login');
    assert.equal(assertSafeNavigationUrl('http://172.16.1.10/', true), 'http://172.16.1.10/');
});

test('Omnibox Query Routing: buildSearchUrl supports all designated engines', () => {
    const query = 'debian 13 virtual browser';
    assert.equal(buildSearchUrl(query, 'google'), 'https://www.google.com/search?q=debian%2013%20virtual%20browser');
    assert.equal(buildSearchUrl(query, 'duckduckgo'), 'https://duckduckgo.com/?q=debian%2013%20virtual%20browser');
    assert.equal(buildSearchUrl(query, 'brave'), 'https://search.brave.com/search?q=debian%2013%20virtual%20browser');
    assert.equal(buildSearchUrl(query, 'bing'), 'https://www.bing.com/search?q=debian%2013%20virtual%20browser');
    assert.equal(buildSearchUrl(query, 'ecosia'), 'https://www.ecosia.org/search?q=debian%2013%20virtual%20browser');
});

test('CSWSH / CSRF Origin Validation: validateOrigin checks request origin and referer', () => {
    const validReq = {
        headers: {
            host: 'browser.example.com',
            origin: 'https://browser.example.com'
        }
    };
    assert.equal(validateOrigin(validReq), true);

    const validRefererReq = {
        headers: {
            host: 'browser.example.com',
            referer: 'https://browser.example.com/app'
        }
    };
    assert.equal(validateOrigin(validRefererReq), true);

    const attackerReq = {
        headers: {
            host: 'browser.example.com',
            origin: 'https://evil-attacker.com'
        }
    };
    assert.equal(validateOrigin(attackerReq), false);

    const emptyOriginReq = {
        headers: {
            host: 'browser.example.com'
        }
    };
    assert.equal(validateOrigin(emptyOriginReq), false);
});

test('Session Lifecycle: isTokenValid enforces creation and idle TTLs', () => {
    const now = Date.now();
    const validMeta = {
        createdAt: now - 1000,
        lastActivity: now - 500,
        ip: '127.0.0.1'
    };
    assert.equal(isTokenValid(validMeta, now), true);

    // Expired absolute TTL (> 24h)
    const expiredMeta = {
        createdAt: now - (25 * 60 * 60 * 1000),
        lastActivity: now - 500,
        ip: '127.0.0.1'
    };
    assert.equal(isTokenValid(expiredMeta, now), false);

    // Expired idle TTL (> 4h)
    const idleMeta = {
        createdAt: now - (2 * 60 * 60 * 1000),
        lastActivity: now - (5 * 60 * 60 * 1000),
        ip: '127.0.0.1'
    };
    assert.equal(isTokenValid(idleMeta, now), false);
});
