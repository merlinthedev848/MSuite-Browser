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
const backBtn          = document.getElementById('back-btn');
const forwardBtn       = document.getElementById('forward-btn');
const reloadBtn        = document.getElementById('reload-btn');
const clipBtn          = document.getElementById('clip-btn');
const clipModal        = document.getElementById('clip-modal');
const clipCloseBtn     = document.getElementById('clip-close-btn');
const clipText         = document.getElementById('clip-text');
const clipPushBtn      = document.getElementById('clip-push-btn');

const settingsBtn       = document.getElementById('settings-btn');
const settingsModal     = document.getElementById('settings-modal');
const settingsCloseBtn  = document.getElementById('settings-close-btn');
const adblockToggle     = document.getElementById('adblock-toggle');
const vpnToggle         = document.getElementById('vpn-toggle');
const uaSelect          = document.getElementById('ua-select');
const customUaInput     = document.getElementById('custom-ua-input');
const clearSessionBtn   = document.getElementById('clear-session-btn');

// Proxy controls
const proxyInput        = document.getElementById('proxy-input');
const proxyApplyBtn     = document.getElementById('proxy-apply-btn');
const proxyClearBtn     = document.getElementById('proxy-clear-btn');

// Zoom controls
const zoomInBtn         = document.getElementById('zoom-in-btn');
const zoomOutBtn        = document.getElementById('zoom-out-btn');
const zoomResetBtn      = document.getElementById('zoom-reset-btn');
const zoomDisplay       = document.getElementById('zoom-level-display');

// Toolbar new buttons
const findBtn           = document.getElementById('find-btn');
const downloadsBtn      = document.getElementById('downloads-btn');
const muteBtn           = document.getElementById('mute-btn');
const muteIconOn        = document.getElementById('mute-icon-on');
const muteIconOff       = document.getElementById('mute-icon-off');

// Downloads panel
const downloadsPanel    = document.getElementById('downloads-panel');
const downloadsCloseBtn = document.getElementById('downloads-close-btn');
const downloadsList     = document.getElementById('downloads-list');

// Upload panel
const uploadPanel       = document.getElementById('upload-panel');
const uploadCloseBtn    = document.getElementById('upload-close-btn');
const uploadPickBtn     = document.getElementById('upload-pick-btn');
const localFileInput    = document.getElementById('local-file-input');
const uploadFilename    = document.getElementById('upload-filename');
const uploadSendBtn     = document.getElementById('upload-send-btn');
const uploadCancelBtn   = document.getElementById('upload-cancel-btn');

// Find bar
const findBar           = document.getElementById('find-bar');
const findInput         = document.getElementById('find-input');
const findCount         = document.getElementById('find-count');
const findPrevBtn       = document.getElementById('find-prev-btn');
const findNextBtn       = document.getElementById('find-next-btn');
const findCloseBtn      = document.getElementById('find-close-btn');

// Progress bar
const loadingProgress   = document.getElementById('loading-progress');

// Bookmarks bar
const bookmarksBar      = document.getElementById('bookmarks-bar');
const bookmarksContainer = document.getElementById('bookmarks-container');
const addBookmarkBtn    = document.getElementById('add-bookmark-btn');

// Quality selector
const qualitySelect     = document.getElementById('quality-select');

// Context menu
const contextMenu       = document.getElementById('context-menu');
const ctxBack           = document.getElementById('ctx-back');
const ctxForward        = document.getElementById('ctx-forward');
const ctxReload         = document.getElementById('ctx-reload');
const ctxNewTab         = document.getElementById('ctx-newtab');
const ctxAdblock        = document.getElementById('ctx-adblock');
const ctxClear          = document.getElementById('ctx-clear');

// ---------- State ----------
let ws = null;
let appInitialized = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 3;
let reconnectTimer = null;
let activeTabId = null;
let loadingTimer = null;
let zoomLevel = 1.0;
let isMuted = false;
let pendingUploadFile = null;

// Double buffer variables for flicker-free streaming
let activeImg = imgA;
let bufferImg = imgB;

// Remote browser resolution — must match server.js viewport
const REMOTE_W = 1920;
const REMOTE_H = 1080;

// ---------- Login ----------
let loginThrottleUntil = 0;
let loginCountdownTimer = null;

function startLoginCountdown(seconds) {
    clearInterval(loginCountdownTimer);
    loginBtn.disabled = true;
    const updateLabel = () => {
        const remaining = Math.ceil((loginThrottleUntil - Date.now()) / 1000);
        if (remaining <= 0) {
            clearInterval(loginCountdownTimer);
            loginBtn.disabled = false;
            loginBtn.querySelector('span').textContent = 'Connect';
            return;
        }
        loginBtn.querySelector('span').textContent = `Wait ${remaining}s…`;
    };
    updateLabel();
    loginCountdownTimer = setInterval(updateLabel, 1000);
}

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Client-side throttle guard
    if (Date.now() < loginThrottleUntil) return;

    // Sanitise input — strip leading/trailing whitespace, enforce max length
    const rawPassword = passwordInput.value;
    if (!rawPassword || rawPassword.length > 256) {
        loginError.textContent = 'Password is required and must be under 256 characters.';
        loginError.classList.remove('hidden');
        return;
    }

    loginBtn.disabled = true;
    loginBtn.querySelector('span').textContent = 'Connecting…';
    loginError.classList.add('hidden');

    try {
        const res = await fetch('/api/login', {
            method:  'POST',
            headers: {
                'Content-Type': 'application/json',
                // Include same-origin header so CSRF origin check passes from browser
                'X-Requested-With': 'XMLHttpRequest'
            },
            // Send the raw value — no client-side hashing (that would be security theatre)
            body: JSON.stringify({ password: rawPassword }),
            credentials: 'same-origin'
        });

        // Parse Retry-After header if present (server signals lockout duration)
        const retryAfter = parseInt(res.headers.get('Retry-After') || '0', 10);
        const data = await res.json();

        if (data.success) {
            // Store token and immediately clear the password field
            sessionStorage.setItem('vb_token', data.token);
            passwordInput.value = '';
            loginScreen.classList.add('hidden');
            appContainer.classList.remove('hidden');
            initApp(data.token);
        } else {
            // Show server error — escape the string to prevent reflected XSS
            const msg = String(data.error || 'Incorrect password').slice(0, 200);
            loginError.textContent = msg;
            loginError.classList.remove('hidden');

            if (retryAfter > 0) {
                // Lock the button for the server-specified duration
                loginThrottleUntil = Date.now() + retryAfter * 1000;
                startLoginCountdown(retryAfter);
            } else if (res.status === 401) {
                // Apply a small client-side delay between attempts regardless
                loginThrottleUntil = Date.now() + 1500;
                setTimeout(() => {
                    loginBtn.disabled = false;
                    loginBtn.querySelector('span').textContent = 'Connect';
                }, 1500);
            } else {
                loginBtn.disabled = false;
                loginBtn.querySelector('span').textContent = 'Connect';
            }
        }
    } catch {
        loginError.textContent = 'Connection error — is the server running?';
        loginError.classList.remove('hidden');
        loginBtn.disabled = false;
        loginBtn.querySelector('span').textContent = 'Connect';
    }
});

// ---------- Main App ----------
function resetToLogin(errorMsg) {
    sessionStorage.removeItem('vb_token');
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    reconnectAttempts = 0;
    appInitialized = false;
    if (ws) {
        try { ws.close(); } catch (_) {}
        ws = null;
    }
    hideOverlay();
    appContainer.classList.add('hidden');
    loginScreen.classList.remove('hidden');
    if (errorMsg) {
        loginError.textContent = errorMsg;
        loginError.classList.remove('hidden');
    }
    loginBtn.disabled = false;
    loginBtn.querySelector('span').textContent = 'Connect';
}

function initApp(token) {
    if (appInitialized) return;
    appInitialized = true;
    reconnectAttempts = 0;

    connectWS(token);
}

function connectWS(token) {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/?token=${token}`);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        reconnectAttempts = 0;
        statusDot.classList.replace('disconnected', 'connected');
        statusText.textContent = 'Connected';
        viewportContainer.focus();
        hideOverlay();
        viewportContainer.classList.add('ready');
    };

    ws.onclose = (event) => {
        // If the socket was closed due to auth failure (code 4001 or 1008 or missing token)
        if (event.code === 4001 || event.code === 1008 || !sessionStorage.getItem('vb_token')) {
            resetToLogin('Session expired or unauthorized. Please log in again.');
            return;
        }

        reconnectAttempts++;
        if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
            resetToLogin('Unable to connect to server. Please log in again.');
            return;
        }

        statusDot.classList.replace('connected', 'disconnected');
        statusText.textContent = `Reconnecting (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`;
        showOverlay(`Reconnecting (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
        viewportContainer.classList.remove('ready');

        // Retry with brief delay
        reconnectTimer = setTimeout(() => connectWS(token), 2000);
    };

    ws.onerror = () => {
        // onclose will fire right after — let that handle UI
    };

    ws.onmessage = (event) => {
        let isBinary = false;
        let blob = null;

        if (event.data instanceof ArrayBuffer) {
            isBinary = true;
            const view = new Uint8Array(event.data);
            let mime = 'image/jpeg';
            // PNG magic bytes check: 89 50 4E 47
            if (view[0] === 0x89 && view[1] === 0x50 && view[2] === 0x4E && view[3] === 0x47) {
                mime = 'image/png';
            }
            blob = new Blob([event.data], { type: mime });
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

            case 'clipboard':
                clipText.value = msg.text;
                clipText.classList.remove('clip-glow-anim');
                void clipText.offsetWidth; // Trigger reflow
                clipText.classList.add('clip-glow-anim');
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(msg.text).catch(() => {});
                }
                break;

            case 'auth_error':
                resetToLogin(msg.error || 'Session expired. Please log in again.');
                break;

            case 'loading_state':
                handleLoadingState(msg.loading);
                break;

            case 'download_ready':
                addDownloadItem(msg.filename, msg.url);
                downloadsPanel.classList.remove('hidden');
                break;

            case 'file_chooser_open':
                uploadPanel.classList.remove('hidden');
                break;

            case 'find_result':
                findCount.textContent = msg.count > 0 ? `${msg.count} match${msg.count > 1 ? 'es' : ''}` : 'No matches';
                break;
        }
    };
}

function handleLoadingState(loading) {
    if (loading) {
        clearTimeout(loadingTimer);
        loadingProgress.style.opacity = '1';
        loadingProgress.style.width = '0%';
        void loadingProgress.offsetWidth; // Trigger reflow
        loadingProgress.style.transition = 'width 2s cubic-bezier(0.1, 0.8, 0.3, 1)';
        loadingProgress.style.width = '90%';
    } else {
        loadingProgress.style.transition = 'width 0.3s ease';
        loadingProgress.style.width = '100%';
        loadingTimer = setTimeout(() => {
            loadingProgress.style.opacity = '0';
            loadingTimer = setTimeout(() => {
                loadingProgress.style.width = '0%';
            }, 300);
        }, 300);
    }
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
        if (tab.isActive) {
            activeTabId = tab.id;
        }
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

    const isCmdOrCtrl = e.ctrlKey || e.metaKey;

    // Ctrl + V (Paste from local desktop clipboard)
    if (isCmdOrCtrl && e.key.toLowerCase() === 'v') {
        e.preventDefault();
        if (navigator.clipboard && navigator.clipboard.readText) {
            navigator.clipboard.readText()
                .then(text => {
                    if (text) sendMsg({ type: 'type', text });
                })
                .catch(() => {
                    // Fallback to clipboard sync modal if permission is not granted
                    clipModal.classList.remove('hidden');
                    clipText.focus();
                    clipText.select();
                });
        } else {
            clipModal.classList.remove('hidden');
            clipText.focus();
            clipText.select();
        }
        return;
    }

    if (isCmdOrCtrl && e.key.toLowerCase() === 't') {
        e.preventDefault();
        sendMsg({ type: 'new_tab' });
        return;
    }
    if (isCmdOrCtrl && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        findBar.classList.remove('hidden');
        findInput.focus();
        findInput.select();
        return;
    }
    if (isCmdOrCtrl && e.key.toLowerCase() === 'w') {
        e.preventDefault();
        if (activeTabId) {
            sendMsg({ type: 'close_tab', tabId: activeTabId });
        }
        return;
    }
    if ((isCmdOrCtrl && e.key.toLowerCase() === 'r') || e.key === 'F5') {
        e.preventDefault();
        sendMsg({ type: 'reload' });
        return;
    }
    if (e.altKey && e.key === 'ArrowLeft') {
        e.preventDefault();
        sendMsg({ type: 'back' });
        return;
    }
    if (e.altKey && e.key === 'ArrowRight') {
        e.preventDefault();
        sendMsg({ type: 'forward' });
        return;
    }

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

// ---------- Navigation Buttons ----------
backBtn.addEventListener('click', () => sendMsg({ type: 'back' }));
forwardBtn.addEventListener('click', () => sendMsg({ type: 'forward' }));
reloadBtn.addEventListener('click', () => sendMsg({ type: 'reload' }));

// ---------- Clipboard Panel ----------
clipBtn.addEventListener('click', () => {
    clipModal.classList.toggle('hidden');
    if (!clipModal.classList.contains('hidden')) {
        clipText.focus();
        clipText.select();
    }
});

clipCloseBtn.addEventListener('click', () => {
    clipModal.classList.add('hidden');
});

clipPushBtn.addEventListener('click', () => {
    const text = clipText.value;
    if (text) {
        sendMsg({ type: 'type', text });
        clipModal.classList.add('hidden');
        viewportContainer.focus();
    }
});

// ---------- Settings Panel ----------
settingsBtn.addEventListener('click', () => {
    settingsModal.classList.toggle('hidden');
    clipModal.classList.add('hidden'); // prevent overlapping
});

settingsCloseBtn.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
});

adblockToggle.addEventListener('change', () => {
    sendMsg({ type: 'toggle_adblocker', enabled: adblockToggle.checked });
});

// ---------- Free VPN (Cloudflare WARP) ----------
vpnToggle.addEventListener('change', () => {
    const enabled = vpnToggle.checked;
    sendMsg({ type: 'toggle_vpn', enabled });
    showOverlay(enabled
        ? '⚡ Connecting to Cloudflare WARP VPN...'
        : '🔓 Disconnecting from WARP VPN...');
    settingsModal.classList.add('hidden');
});

// ---------- Proxy Settings ----------
proxyApplyBtn.addEventListener('click', () => {
    const proxy = proxyInput.value.trim();
    if (!proxy) return;
    sendMsg({ type: 'set_proxy', proxy });
    showOverlay('Applying proxy & restarting context...');
    settingsModal.classList.add('hidden');
});

proxyClearBtn.addEventListener('click', () => {
    proxyInput.value = '';
    sendMsg({ type: 'set_proxy', proxy: '' });
    showOverlay('Clearing proxy & restarting context...');
    settingsModal.classList.add('hidden');
});

proxyInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') proxyApplyBtn.click();
});

// ---------- Zoom Controls ----------
function applyZoom(level) {
    zoomLevel = Math.min(5.0, Math.max(0.2, level));
    zoomDisplay.textContent = Math.round(zoomLevel * 100) + '%';
    sendMsg({ type: 'set_zoom', zoom: zoomLevel });
}

zoomInBtn.addEventListener('click', () => applyZoom(zoomLevel + 0.1));
zoomOutBtn.addEventListener('click', () => applyZoom(zoomLevel - 0.1));
zoomResetBtn.addEventListener('click', () => applyZoom(1.0));

// ---------- Mute Toggle ----------
muteBtn.addEventListener('click', () => {
    isMuted = !isMuted;
    sendMsg({ type: 'set_mute', muted: isMuted });
    muteIconOn.style.display = isMuted ? 'none' : '';
    muteIconOff.style.display = isMuted ? '' : 'none';
    muteBtn.title = isMuted ? 'Unmute Tab' : 'Mute Tab';
});

// ---------- Find In Page ----------
findBtn.addEventListener('click', () => {
    findBar.classList.toggle('hidden');
    if (!findBar.classList.contains('hidden')) {
        findInput.focus();
        findInput.select();
    } else {
        sendMsg({ type: 'find', query: '' });
        findCount.textContent = '';
    }
});

findCloseBtn.addEventListener('click', () => {
    findBar.classList.add('hidden');
    sendMsg({ type: 'find', query: '' });
    findCount.textContent = '';
});

let findDebounce = null;
findInput.addEventListener('input', () => {
    clearTimeout(findDebounce);
    findDebounce = setTimeout(() => {
        sendMsg({ type: 'find', query: findInput.value });
    }, 250);
});

findInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        sendMsg({ type: 'find_next', forward: !e.shiftKey });
    } else if (e.key === 'Escape') {
        findCloseBtn.click();
    }
});

findNextBtn.addEventListener('click', () => sendMsg({ type: 'find_next', forward: true }));
findPrevBtn.addEventListener('click', () => sendMsg({ type: 'find_next', forward: false }));

// ---------- Downloads Panel ----------
downloadsBtn.addEventListener('click', () => {
    downloadsPanel.classList.toggle('hidden');
});

downloadsCloseBtn.addEventListener('click', () => {
    downloadsPanel.classList.add('hidden');
});

function addDownloadItem(filename, url) {
    const empty = downloadsList.querySelector('.downloads-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'download-item';
    item.innerHTML = `
        <span class="download-item-name" title="${filename}">📄 ${filename}</span>
        <a class="download-item-link" href="${url}" download="${filename}" target="_blank">Save ↓</a>
    `;
    downloadsList.prepend(item);
}

// ---------- File Upload Panel ----------
uploadPickBtn.addEventListener('click', () => localFileInput.click());

localFileInput.addEventListener('change', () => {
    const file = localFileInput.files[0];
    if (!file) return;
    pendingUploadFile = file;
    uploadFilename.textContent = file.name;
    uploadSendBtn.disabled = false;
});

uploadSendBtn.addEventListener('click', () => {
    if (!pendingUploadFile) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const base64 = e.target.result.split(',')[1];
        sendMsg({ type: 'file_uploaded', name: pendingUploadFile.name, data: base64 });
        uploadPanel.classList.add('hidden');
        pendingUploadFile = null;
        localFileInput.value = '';
        uploadFilename.textContent = 'No file chosen';
        uploadSendBtn.disabled = true;
    };
    reader.readAsDataURL(pendingUploadFile);
});

uploadCancelBtn.addEventListener('click', () => {
    uploadPanel.classList.add('hidden');
    pendingUploadFile = null;
    localFileInput.value = '';
    uploadFilename.textContent = 'No file chosen';
    uploadSendBtn.disabled = true;
});

uploadCloseBtn.addEventListener('click', () => {
    uploadPanel.classList.add('hidden');
});

uaSelect.addEventListener('change', () => {
    const val = uaSelect.value;
    if (val === 'custom') {
        customUaInput.classList.remove('hidden');
        customUaInput.focus();
    } else {
        customUaInput.classList.add('hidden');
        sendMsg({ type: 'set_useragent', userAgent: val });
    }
});

customUaInput.addEventListener('blur', () => {
    const ua = customUaInput.value.trim();
    if (ua) {
        sendMsg({ type: 'set_useragent', userAgent: ua });
    }
});

customUaInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        customUaInput.blur();
        viewportContainer.focus();
    }
});

clearSessionBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear session cookies, permissions, and cache?')) {
        sendMsg({ type: 'clear_session' });
        settingsModal.classList.add('hidden');
    }
});


// ---------- Bookmarks Bar ----------
const DEFAULT_BOOKMARKS = [
    { name: 'Google', url: 'https://www.google.com' },
    { name: 'YouTube', url: 'https://www.youtube.com' },
    { name: 'GitHub', url: 'https://github.com' }
];

let bookmarks = [];

function loadBookmarks() {
    try {
        const stored = localStorage.getItem('vb_bookmarks');
        if (stored) {
            bookmarks = JSON.parse(stored);
        } else {
            bookmarks = [...DEFAULT_BOOKMARKS];
            saveBookmarks();
        }
    } catch {
        bookmarks = [...DEFAULT_BOOKMARKS];
    }
    renderBookmarks();
}

function saveBookmarks() {
    try {
        localStorage.setItem('vb_bookmarks', JSON.stringify(bookmarks));
    } catch (_) {}
}

function renderBookmarks() {
    bookmarksContainer.innerHTML = '';
    bookmarks.forEach((bm, index) => {
        const item = document.createElement('div');
        item.className = 'bookmark-item';
        
        // Simple favicon helper
        const icon = document.createElement('img');
        icon.className = 'bookmark-item-icon';
        
        let domain = bm.url;
        try { domain = new URL(bm.url).hostname; } catch (_) {}
        icon.src = `https://www.google.com/s2/favicons?domain=${domain}&sz=16`;
        icon.onerror = () => { icon.style.display = 'none'; };

        const nameSpan = document.createElement('span');
        nameSpan.textContent = bm.name;

        item.appendChild(icon);
        item.appendChild(nameSpan);

        item.addEventListener('click', () => {
            urlInput.value = bm.url;
            navigate();
        });

        // Right click to delete bookmark
        item.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            if (confirm(`Remove bookmark "${bm.name}"?`)) {
                bookmarks.splice(index, 1);
                saveBookmarks();
                renderBookmarks();
            }
        });

        bookmarksContainer.appendChild(item);
    });
}

addBookmarkBtn.addEventListener('click', () => {
    const urlVal = urlInput.value.trim();
    if (!urlVal) return;

    let targetUrl = urlVal;
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = 'https://' + targetUrl;
    }

    let hostname = 'Bookmark';
    try {
        hostname = new URL(targetUrl).hostname.replace('www.', '');
    } catch (_) {
        hostname = targetUrl;
    }

    const name = prompt('Enter bookmark name:', hostname);
    if (name === null) return; // cancelled

    bookmarks.push({ name: name.trim() || hostname, url: targetUrl });
    saveBookmarks();
    renderBookmarks();
});

// Initialize bookmarks
loadBookmarks();

// ---------- Stream Performance Settings ----------
qualitySelect.addEventListener('change', () => {
    const val = qualitySelect.value;
    if (val === 'png') {
        sendMsg({ type: 'set_stream_quality', format: 'png' });
    } else if (val === 'jpeg_98') {
        sendMsg({ type: 'set_stream_quality', format: 'jpeg', quality: 98 });
    } else {
        sendMsg({ type: 'set_stream_quality', format: 'jpeg', quality: 90 });
    }
});

// ---------- Custom Context Menu ----------
overlay.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    contextMenu.classList.remove('hidden');
    
    // Position menu exactly under cursor, checking boundaries
    const menuW = 180;
    const menuH = 200;
    let x = e.clientX;
    let y = e.clientY;

    if (x + menuW > window.innerWidth) x = window.innerWidth - menuW - 10;
    if (y + menuH > window.innerHeight) y = window.innerHeight - menuH - 10;

    contextMenu.style.left = `${x}px`;
    contextMenu.style.top = `${y}px`;
});

// Hide context menu on left click anywhere
document.addEventListener('click', () => {
    contextMenu.classList.add('hidden');
});

// Context Menu Action Listeners
ctxBack.addEventListener('click', () => sendMsg({ type: 'back' }));
ctxForward.addEventListener('click', () => sendMsg({ type: 'forward' }));
ctxReload.addEventListener('click', () => sendMsg({ type: 'reload' }));
ctxNewTab.addEventListener('click', () => sendMsg({ type: 'new_tab' }));
ctxAdblock.addEventListener('click', () => {
    adblockToggle.checked = !adblockToggle.checked;
    sendMsg({ type: 'toggle_adblocker', enabled: adblockToggle.checked });
});
ctxClear.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear session cookies, permissions, and cache?')) {
        sendMsg({ type: 'clear_session' });
    }
});

// ---------- Windows-Style Titlebar Window Control Actions ----------
const winMinimize = document.querySelector('.win-minimize');
const winMaximize = document.querySelector('.win-maximize');
const winClose    = document.querySelector('.win-close');

if (winMinimize) {
    winMinimize.addEventListener('click', () => {
        // Minimize: logout/return to login screen cleanly
        if (ws) ws.close();
        appContainer.classList.add('hidden');
        loginScreen.classList.remove('hidden');
        passwordInput.value = '';
        passwordInput.focus();
    });
}
if (winMaximize) {
    winMaximize.addEventListener('click', () => {
        // Maximize: Request full screen
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(() => {});
        } else {
            document.exitFullscreen().catch(() => {});
        }
    });
}
if (winClose) {
    winClose.addEventListener('click', () => {
        if (confirm('Are you sure you want to close the browser session and exit?')) {
            if (ws) ws.close();
            appContainer.classList.add('hidden');
            loginScreen.classList.remove('hidden');
            passwordInput.value = '';
        }
    });
}

// ---------- Bootstrap Stored Session ----------
const storedToken = sessionStorage.getItem('vb_token');
if (storedToken) {
    loginScreen.classList.add('hidden');
    appContainer.classList.remove('hidden');
    initApp(storedToken);
}
