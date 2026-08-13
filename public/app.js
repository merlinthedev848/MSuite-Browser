// ---------- DOM References ----------
const loginScreen      = document.getElementById('login-screen');
const loginForm        = document.getElementById('login-form');
const passwordInput    = document.getElementById('password-input');
const loginError       = document.getElementById('login-error');
const loginBtn         = document.getElementById('login-btn');
const appContainer     = document.getElementById('app-container');
const viewportContainer = document.getElementById('viewport-container');
const imgA             = document.getElementById('screencast-a');
const imgB             = document.getElementById('screencast-b');
const overlay          = document.getElementById('interaction-overlay');
const urlInput         = document.getElementById('url-input');
const goBtn            = document.getElementById('go-btn');
const statusDot        = document.querySelector('.status-dot');
const statusText       = document.querySelector('.status-text');
const loadingOverlay   = document.getElementById('loading-overlay');
const loadingText      = document.getElementById('loading-text');
const tabsContainer    = document.getElementById('tabs-container');
const newTabBtn        = document.getElementById('new-tab-btn');

// ---------- State ----------
let ws = null;
let appInitialized = false;
let reconnectTimer = null;

// Double buffer variables for flicker-free streaming
let activeImg = imgA;
let bufferImg = imgB;

// Remote browser resolution — must match server.js viewport
const REMOTE_W = 1920;
const REMOTE_H = 1080;

// ---------- Session Persistence ----------
const storedToken = sessionStorage.getItem('vb_token');
if (storedToken) {
    loginScreen.classList.add('hidden');
    appContainer.classList.remove('hidden');
    initApp(storedToken);
}

// ---------- Login ----------
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginBtn.disabled = true;
    loginError.classList.add('hidden');

    try {
        const res  = await fetch('/api/login', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ password: passwordInput.value })
        });
        const data = await res.json();

        if (data.success) {
            sessionStorage.setItem('vb_token', data.token);
            loginScreen.classList.add('hidden');
            appContainer.classList.remove('hidden');
            initApp(data.token);
        } else {
            loginError.textContent = data.error || 'Invalid password';
            loginError.classList.remove('hidden');
        }
    } catch {
        loginError.textContent = 'Connection error — is the server running?';
        loginError.classList.remove('hidden');
    } finally {
        loginBtn.disabled = false;
    }
});

// ---------- Main App ----------
function initApp(token) {
    if (appInitialized) return;
    appInitialized = true;

    connectWS(token);
}

function connectWS(token) {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/?token=${token}`);
    ws.binaryType = 'blob';

    ws.onopen = () => {
        statusDot.classList.replace('disconnected', 'connected');
        statusText.textContent = 'Connected';
        viewportContainer.focus();
    };

    ws.onclose = () => {
        statusDot.classList.replace('connected', 'disconnected');
        statusText.textContent = 'Reconnecting...';
        showOverlay('Reconnecting...');
        viewportContainer.classList.remove('ready');

        // Retry immediately with the same token — no login screen flash
        reconnectTimer = setTimeout(() => connectWS(token), 3000);
    };

    ws.onerror = () => {
        // onclose will fire right after — let that handle UI
    };

    ws.onmessage = (event) => {
        let isBinary = false;
        let blob = null;

        if (event.data instanceof Blob) {
            isBinary = true;
            // Explicitly force image/jpeg type so the browser's native decoder uses the fast path
            blob = event.data.type === 'image/jpeg' ? event.data : new Blob([event.data], { type: 'image/jpeg' });
        } else if (event.data instanceof ArrayBuffer) {
            isBinary = true;
            blob = new Blob([event.data], { type: 'image/jpeg' });
        }

        if (isBinary && blob) {
            const url = URL.createObjectURL(blob);
            
            bufferImg.onload = () => {
                // Swap active and buffer images
                bufferImg.classList.add('active');
                activeImg.classList.remove('active');

                // Toggle references
                const temp = activeImg;
                activeImg = bufferImg;
                bufferImg = temp;

                // Revoke old URL of the new bufferImg (which was the old activeImg)
                if (bufferImg.dataset.srcUrl) {
                    URL.revokeObjectURL(bufferImg.dataset.srcUrl);
                }
                // Save current URL to revoke on the next frame swap
                activeImg.dataset.srcUrl = url;

                if (!viewportContainer.classList.contains('ready')) {
                    hideOverlay();
                    viewportContainer.classList.add('ready');
                }

                sendMsg({ type: 'frame_ack' });
            };

            bufferImg.onerror = () => {
                URL.revokeObjectURL(url);
                sendMsg({ type: 'frame_ack' });
            };

            bufferImg.src = url;
            return;
        }

        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }

        switch (msg.type) {
            case 'url_changed':
                if (document.activeElement !== urlInput) {
                    urlInput.value = msg.url;
                }
                break;

            case 'tab_state':
                renderTabs(msg.tabs);
                break;

            case 'cursor':
                overlay.style.cursor = msg.cursor || 'default';
                break;
        }
    };
}

// ---------- Overlay ----------
function showOverlay(text) {
    if (loadingText) loadingText.textContent = text || 'Loading...';
    loadingOverlay.classList.remove('hidden');
}
function hideOverlay() {
    loadingOverlay.classList.add('hidden');
}

// ---------- Messaging ----------
function sendMsg(msg) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msg));
    }
}

// ---------- Tabs ----------
const tabDomMap = new Map(); // tabId -> tabEl

function renderTabs(tabs) {
    const seenIds = new Set();

    tabs.forEach(tab => {
        seenIds.add(tab.id);
        let tabEl = tabDomMap.get(tab.id);

        if (!tabEl) {
            // Create new tab element
            tabEl = document.createElement('div');
            tabEl.dataset.tabId = tab.id;

            const iconEl = document.createElement('img');
            iconEl.className = 'tab-icon';
            iconEl.style.display = 'none';
            iconEl.onerror = () => { iconEl.style.display = 'none'; };

            const titleEl = document.createElement('span');
            titleEl.className = 'tab-title';

            const closeBtn = document.createElement('button');
            closeBtn.className = 'tab-close';
            closeBtn.setAttribute('aria-label', 'Close tab');
            closeBtn.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';

            tabEl.appendChild(iconEl);
            tabEl.appendChild(titleEl);
            tabEl.appendChild(closeBtn);

            tabEl.addEventListener('click', () => {
                if (!tabEl.classList.contains('active')) {
                    showOverlay('Switching tabs...');
                    viewportContainer.classList.remove('ready');
                    sendMsg({ type: 'switch_tab', tabId: tab.id });
                }
            });

            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                sendMsg({ type: 'close_tab', tabId: tab.id });
            });

            tabDomMap.set(tab.id, tabEl);
            tabsContainer.appendChild(tabEl);
        }

        // Diff-update: only change what actually changed
        const iconEl  = tabEl.querySelector('.tab-icon');
        const titleEl = tabEl.querySelector('.tab-title');

        const newTitle = tab.title || 'New Tab';
        if (titleEl.textContent !== newTitle) titleEl.textContent = newTitle;

        if (tab.favicon && iconEl.src !== tab.favicon) {
            iconEl.src = tab.favicon;
            iconEl.style.display = '';
        }

        const isActive = tab.isActive;
        tabEl.className = `tab${isActive ? ' active' : ''}`;
    });

    // Remove tabs that no longer exist
    for (const [id, el] of tabDomMap) {
        if (!seenIds.has(id)) {
            el.remove();
            tabDomMap.delete(id);
        }
    }

    // Ensure DOM order matches server order
    tabs.forEach(tab => {
        const el = tabDomMap.get(tab.id);
        if (el) tabsContainer.appendChild(el);
    });
}

newTabBtn.addEventListener('click', () => sendMsg({ type: 'new_tab' }));

// ---------- Coordinate Mapping ----------
function getMappedCoords(e) {
    const rect = overlay.getBoundingClientRect();
    return {
        x: Math.round((e.clientX - rect.left) * (REMOTE_W / rect.width)),
        y: Math.round((e.clientY - rect.top)  * (REMOTE_H / rect.height))
    };
}

const mapButton = (e) => ['left', 'middle', 'right'][e.button] ?? 'left';

// ---------- Mouse Events ----------
let lastMoveTime = 0;
overlay.addEventListener('mousemove', (e) => {
    const now = performance.now();
    if (now - lastMoveTime < 33) return; // Cap at ~30fps
    lastMoveTime = now;
    const c = getMappedCoords(e);
    sendMsg({ type: 'mousemove', x: c.x, y: c.y });
});

overlay.addEventListener('mousedown', (e) => {
    e.preventDefault();
    viewportContainer.focus();
    const c = getMappedCoords(e);
    sendMsg({ type: 'mousedown', x: c.x, y: c.y, button: mapButton(e) });
});

overlay.addEventListener('mouseup', (e) => {
    const c = getMappedCoords(e);
    sendMsg({ type: 'mouseup', x: c.x, y: c.y, button: mapButton(e) });
});

overlay.addEventListener('contextmenu', e => e.preventDefault());

overlay.addEventListener('wheel', (e) => {
    e.preventDefault();
    sendMsg({ type: 'wheel', deltaX: e.deltaX, deltaY: e.deltaY });
}, { passive: false });

// ---------- Keyboard ----------
function getModifiers(e) {
    const mods = [];
    if (e.ctrlKey)  mods.push('Control');
    if (e.shiftKey) mods.push('Shift');
    if (e.altKey)   mods.push('Alt');
    if (e.metaKey)  mods.push('Meta');
    return mods;
}

const INTERCEPT_KEYS = new Set([
    'Tab', 'Backspace', 'Delete', 'Escape', 'Enter', 'Space',
    'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
    'Home', 'End', 'PageUp', 'PageDown',
    'F1','F2','F3','F4','F5','F6','F7','F8','F9','F10','F11','F12'
]);

window.addEventListener('keydown', (e) => {
    if (document.activeElement === urlInput || document.activeElement === passwordInput) return;
    if (document.activeElement !== viewportContainer) return;

    if (e.ctrlKey || e.metaKey || e.altKey || INTERCEPT_KEYS.has(e.key)) {
        e.preventDefault();
    }
    sendMsg({ type: 'keydown', key: e.key, modifiers: getModifiers(e) });
}, { passive: false });

window.addEventListener('keyup', (e) => {
    if (document.activeElement === urlInput || document.activeElement === passwordInput) return;
    if (document.activeElement !== viewportContainer) return;
    sendMsg({ type: 'keyup', key: e.key, modifiers: getModifiers(e) });
});

window.addEventListener('paste', (e) => {
    if (document.activeElement !== viewportContainer) return;
    const text = e.clipboardData?.getData('text');
    if (text) sendMsg({ type: 'type', text });
});

// ---------- URL Bar ----------
function navigate() {
    const input = urlInput.value.trim();
    if (!input) return;
    sendMsg({ type: 'goto', url: input });
    viewportContainer.focus();
}

goBtn.addEventListener('click', navigate);

urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')  { e.preventDefault(); navigate(); }
    if (e.key === 'Escape') { viewportContainer.focus(); }
});

urlInput.addEventListener('focus', () => urlInput.select());
