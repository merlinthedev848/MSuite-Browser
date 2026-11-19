// ---------- DOM References ----------
const loginScreen        = document.getElementById('login-screen');
const loginForm          = document.getElementById('login-form');
const passwordInput      = document.getElementById('password-input');
const loginError         = document.getElementById('login-error');
const loginBtn           = document.getElementById('login-btn');
const appContainer       = document.getElementById('app-container');
const viewportContainer  = document.getElementById('viewport-container');
const canvas             = document.getElementById('screencast-canvas');
const ctx                = canvas.getContext('2d', { alpha: false, desynchronized: true });
const overlay            = document.getElementById('interaction-overlay');
const urlInput           = document.getElementById('url-input');
const goBtn              = document.getElementById('go-btn');
const statusDot          = document.querySelector('.status-dot');
const statusText         = document.querySelector('.status-text');
const loadingOverlay     = document.getElementById('loading-overlay');
const loadingText        = document.getElementById('loading-text');
const tabsContainer      = document.getElementById('tabs-container');
const newTabBtn          = document.getElementById('new-tab-btn');
const backBtn            = document.getElementById('back-btn');
const forwardBtn         = document.getElementById('forward-btn');
const reloadBtn          = document.getElementById('reload-btn');

// Security Badge & Omnibox Tools
const securityBadge      = document.getElementById('security-badge');
const securityBadgeText  = document.getElementById('security-badge-text');
const securityModal      = document.getElementById('security-modal');
const securityCloseBtn   = document.getElementById('security-close-btn');
const secAdblockVal      = document.getElementById('sec-adblock-val');
const secTransportVal    = document.getElementById('sec-transport-val');

// Search Engine Selector
const searchEngineBtn    = document.getElementById('search-engine-btn');
const searchEngineIcon   = document.getElementById('search-engine-icon');
const searchEngineMenu   = document.getElementById('search-engine-menu');

// Page Tools & Device Emulation
const pageToolsBtn       = document.getElementById('page-tools-btn');
const pageToolsMenu      = document.getElementById('page-tools-menu');
const deviceBtn          = document.getElementById('device-btn');
const deviceMenu         = document.getElementById('device-menu');
const toolScreenshotView = document.getElementById('tool-screenshot-viewport');
const toolScreenshotFull = document.getElementById('tool-screenshot-full');
const toolExportPdf      = document.getElementById('tool-export-pdf');
const toolInvertDark     = document.getElementById('tool-invert-dark');
const toolToggleHud      = document.getElementById('tool-toggle-hud');
const toolShortcuts      = document.getElementById('tool-shortcuts');
const shortcutsModal     = document.getElementById('shortcuts-modal');
const shortcutsCloseBtn  = document.getElementById('shortcuts-close-btn');

// Performance HUD
const perfHud            = document.getElementById('perf-hud');
const hudFps             = document.getElementById('hud-fps');
const hudRtt             = document.getElementById('hud-rtt');
const hudRes             = document.getElementById('hud-res');
const hudDropped         = document.getElementById('hud-dropped');

// DevTools Drawer
const devtoolsBtn        = document.getElementById('devtools-btn');
const devtoolsBadge      = document.getElementById('devtools-badge');
const devtoolsDrawer     = document.getElementById('devtools-drawer');
const devtoolsCloseBtn   = document.getElementById('devtools-close-btn');
const devtoolsClearBtn   = document.getElementById('devtools-clear-btn');
const devtoolsTabConsole = document.getElementById('devtools-tab-console');
const devtoolsTabNetwork = document.getElementById('devtools-tab-network');
const devtoolsConsolePane= document.getElementById('devtools-console-pane');
const devtoolsNetworkPane= document.getElementById('devtools-network-pane');
const consoleLogs        = document.getElementById('console-logs');
const networkLogs        = document.getElementById('network-logs');
const consoleCount       = document.getElementById('console-count');
const networkCount       = document.getElementById('network-count');

// History Drawer
const historyBtn         = document.getElementById('history-btn');
const historyDrawer      = document.getElementById('history-drawer');
const historyCloseBtn    = document.getElementById('history-close-btn');
const historyClearBtn    = document.getElementById('history-clear-btn');
const historySearchInput = document.getElementById('history-search-input');
const historyList        = document.getElementById('history-list');

// Clipboard modal
const clipBtn            = document.getElementById('clip-btn');
const clipModal          = document.getElementById('clip-modal');
const clipCloseBtn       = document.getElementById('clip-close-btn');
const clipText           = document.getElementById('clip-text');
const clipPushBtn        = document.getElementById('clip-push-btn');

// Settings modal
const settingsBtn        = document.getElementById('settings-btn');
const settingsModal      = document.getElementById('settings-modal');
const settingsCloseBtn   = document.getElementById('settings-close-btn');
const adblockToggle      = document.getElementById('adblock-toggle');
const vpnToggle          = document.getElementById('vpn-toggle');
const uaSelect           = document.getElementById('ua-select');
const customUaInput      = document.getElementById('custom-ua-input');
const clearSessionBtn    = document.getElementById('clear-session-btn');
const viewCookiesBtn     = document.getElementById('view-cookies-btn');
const cookiesModal       = document.getElementById('cookies-modal');
const cookiesCloseBtn    = document.getElementById('cookies-close-btn');
const cookiesList        = document.getElementById('cookies-list');
const cookiesClearAllBtn = document.getElementById('cookies-clear-all-btn');

// Proxy controls
const proxyInput         = document.getElementById('proxy-input');
const proxyApplyBtn      = document.getElementById('proxy-apply-btn');
const proxyClearBtn      = document.getElementById('proxy-clear-btn');

// Zoom controls
const zoomInBtn          = document.getElementById('zoom-in-btn');
const zoomOutBtn         = document.getElementById('zoom-out-btn');
const zoomResetBtn       = document.getElementById('zoom-reset-btn');
const zoomDisplay        = document.getElementById('zoom-level-display');

// Toolbar buttons
const findBtn            = document.getElementById('find-btn');
const downloadsBtn       = document.getElementById('downloads-btn');
const muteBtn            = document.getElementById('mute-btn');
const muteIconOn         = document.getElementById('mute-icon-on');
const muteIconOff        = document.getElementById('mute-icon-off');

// Downloads panel
const downloadsPanel     = document.getElementById('downloads-panel');
const downloadsCloseBtn  = document.getElementById('downloads-close-btn');
const downloadsList      = document.getElementById('downloads-list');

// Upload panel
const uploadPanel        = document.getElementById('upload-panel');
const uploadCloseBtn     = document.getElementById('upload-close-btn');
const uploadPickBtn      = document.getElementById('upload-pick-btn');
const localFileInput     = document.getElementById('local-file-input');
const uploadFilename     = document.getElementById('upload-filename');
const uploadSendBtn      = document.getElementById('upload-send-btn');
const uploadCancelBtn    = document.getElementById('upload-cancel-btn');

// Find bar
const findBar            = document.getElementById('find-bar');
const findInput          = document.getElementById('find-input');
const findCount          = document.getElementById('find-count');
const findPrevBtn        = document.getElementById('find-prev-btn');
const findNextBtn        = document.getElementById('find-next-btn');
const findCloseBtn       = document.getElementById('find-close-btn');

// Dialog modal
const dialogModal        = document.getElementById('dialog-modal');
const dialogTitle        = document.getElementById('dialog-title');
const dialogMessage      = document.getElementById('dialog-message');
const dialogInputGroup   = document.getElementById('dialog-input-group');
const dialogInput        = document.getElementById('dialog-input');
const dialogOkBtn        = document.getElementById('dialog-ok-btn');
const dialogCancelBtn    = document.getElementById('dialog-cancel-btn');

// Progress bar
const loadingProgress    = document.getElementById('loading-progress');

// Bookmarks bar
const bookmarksBar       = document.getElementById('bookmarks-bar');
const bookmarksContainer = document.getElementById('bookmarks-container');
const addBookmarkBtn     = document.getElementById('add-bookmark-btn');

// Quality selector
const qualitySelect      = document.getElementById('quality-select');

// Context menus
const contextMenu        = document.getElementById('context-menu');
const ctxBack            = document.getElementById('ctx-back');
const ctxForward         = document.getElementById('ctx-forward');
const ctxReload          = document.getElementById('ctx-reload');
const ctxNewTab          = document.getElementById('ctx-newtab');
const ctxDuplicate       = document.getElementById('ctx-duplicate');
const ctxScreenshot      = document.getElementById('ctx-screenshot');
const ctxAdblock         = document.getElementById('ctx-adblock');
const ctxClear           = document.getElementById('ctx-clear');

const tabContextMenu     = document.getElementById('tab-context-menu');
const tabCtxReload       = document.getElementById('tab-ctx-reload');
const tabCtxDuplicate    = document.getElementById('tab-ctx-duplicate');
const tabCtxMute         = document.getElementById('tab-ctx-mute');
const tabCtxClose        = document.getElementById('tab-ctx-close');
const tabCtxCloseOthers  = document.getElementById('tab-ctx-close-others');

// Windows-style titlebar controls
const winMinimize        = document.querySelector('.win-minimize');
const winMaximize        = document.querySelector('.win-maximize');
const winClose           = document.querySelector('.win-close');

// ---------- Client State & Metrics ----------
let ws = null;
let appInitialized = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
let reconnectTimer = null;
let activeTabId = null;
let contextTargetTabId = null;
let loadingTimer = null;
let zoomLevel = 1.0;
let isMuted = false;
let isDarkInverted = false;
let selectedSearchEngine = localStorage.getItem('vb_search_engine') || 'google';

// Viewport & Resolution
let remoteWidth = 1920;
let remoteHeight = 1080;
canvas.width = remoteWidth;
canvas.height = remoteHeight;

// Performance Metrics
let frameCount = 0;
let lastFpsTime = performance.now();
let lastFrameSentTime = 0;
let latencyMs = 0;
let droppedFramesTotal = 0;

// DevTools Data
let consoleEntries = [];
let networkEntries = [];

// ---------- Login Flow ----------
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
            loginBtn.querySelector('span').textContent = 'Connect Session';
            return;
        }
        loginBtn.querySelector('span').textContent = `Wait ${remaining}s…`;
    };
    updateLabel();
    loginCountdownTimer = setInterval(updateLabel, 1000);
}

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (Date.now() < loginThrottleUntil) return;

    const rawPassword = passwordInput.value;
    if (!rawPassword || rawPassword.length > 256) {
        loginError.textContent = 'Password is required (under 256 characters).';
        loginError.classList.remove('hidden');
        return;
    }

    loginBtn.disabled = true;
    loginBtn.querySelector('span').textContent = 'Connecting…';
    loginError.classList.add('hidden');

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ password: rawPassword }),
            credentials: 'same-origin'
        });

        const retryAfter = parseInt(res.headers.get('Retry-After') || '0', 10);
        const data = await res.json().catch(() => ({ success: false, error: 'Malformed response' }));

        if (data.success) {
            sessionStorage.setItem('vb_token', '1');
            passwordInput.value = '';
            loginScreen.classList.add('hidden');
            appContainer.classList.remove('hidden');
            initApp();
        } else {
            const msg = String(data.error || 'Incorrect password').slice(0, 200);
            loginError.textContent = msg;
            loginError.classList.remove('hidden');

            if (retryAfter > 0) {
                loginThrottleUntil = Date.now() + retryAfter * 1000;
                startLoginCountdown(retryAfter);
            } else {
                loginThrottleUntil = Date.now() + 1000;
                setTimeout(() => {
                    loginBtn.disabled = false;
                    loginBtn.querySelector('span').textContent = 'Connect Session';
                }, 1000);
            }
        }
    } catch {
        loginError.textContent = 'Connection error — check server status.';
        loginError.classList.remove('hidden');
        loginBtn.disabled = false;
        loginBtn.querySelector('span').textContent = 'Connect Session';
    }
});

// ---------- Session & WebSocket Lifecycle ----------
async function logoutServer() {
    try {
        await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (_) {}
}

function resetToLogin(errorMsg, { revoke = true } = {}) {
    sessionStorage.removeItem('vb_token');
    if (revoke) logoutServer();
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
    loginBtn.querySelector('span').textContent = 'Connect Session';
}

function initApp() {
    if (appInitialized) return;
    appInitialized = true;
    reconnectAttempts = 0;
    connectWS();
}

function connectWS() {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/`);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        reconnectAttempts = 0;
        statusDot.classList.replace('disconnected', 'connected');
        statusText.textContent = 'Connected';
        viewportContainer.focus();
        hideOverlay();
        viewportContainer.classList.add('ready');
        sendMsg({ type: 'set_search_engine', engine: selectedSearchEngine });
    };

    ws.onclose = (event) => {
        if (event.code === 4001 || event.code === 1008 || !sessionStorage.getItem('vb_token')) {
            resetToLogin('Session expired or unauthorized. Please log in again.');
            return;
        }

        reconnectAttempts++;
        if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
            resetToLogin('Connection lost. Please log in again.');
            return;
        }

        statusDot.classList.replace('connected', 'disconnected');
        statusText.textContent = `Reconnecting (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`;
        showOverlay(`Reconnecting (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
        viewportContainer.classList.remove('ready');

        reconnectTimer = setTimeout(() => connectWS(), 2000);
    };

    ws.onerror = () => {};

    ws.onmessage = async (event) => {
        // High-Performance Hardware-Accelerated Canvas Rendering
        if (event.data instanceof ArrayBuffer) {
            const now = performance.now();
            if (lastFrameSentTime > 0) {
                latencyMs = Math.round(now - lastFrameSentTime);
                hudRtt.textContent = `${latencyMs} ms`;
            }

            const view = new Uint8Array(event.data);
            let mime = 'image/jpeg';
            if (view[0] === 0x89 && view[1] === 0x50 && view[2] === 0x4E && view[3] === 0x47) {
                mime = 'image/png';
            }

            const blob = new Blob([event.data], { type: mime });
            try {
                const bitmap = await createImageBitmap(blob);
                if (canvas.width !== remoteWidth || canvas.height !== remoteHeight) {
                    canvas.width = remoteWidth;
                    canvas.height = remoteHeight;
                }
                ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
                bitmap.close(); // Immediate GPU memory reclamation

                if (!viewportContainer.classList.contains('ready')) {
                    hideOverlay();
                    viewportContainer.classList.add('ready');
                }

                // FPS & Metrics Accounting
                frameCount++;
                if (now - lastFpsTime >= 1000) {
                    const fps = Math.round((frameCount * 1000) / (now - lastFpsTime));
                    hudFps.textContent = String(fps);
                    frameCount = 0;
                    lastFpsTime = now;
                }

                lastFrameSentTime = performance.now();
                sendMsg({ type: 'frame_ack' });
            } catch (_) {
                sendMsg({ type: 'frame_ack' });
            }
            return;
        }

        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }

        switch (msg.type) {
            case 'viewport_dimensions':
                if (typeof msg.width === 'number' && typeof msg.height === 'number') {
                    remoteWidth = msg.width;
                    remoteHeight = msg.height;
                    canvas.width = remoteWidth;
                    canvas.height = remoteHeight;
                    hudRes.textContent = `${remoteWidth}x${remoteHeight}`;
                }
                break;

            case 'url_changed':
                if (document.activeElement !== urlInput) {
                    urlInput.value = msg.url;
                }
                updateSecurityBadge(msg.url);
                recordHistory(msg.url);
                break;

            case 'tab_state':
                renderTabs(msg.tabs);
                break;

            case 'tab_audio_state':
                updateTabAudioIndicator(msg.tabId, msg.isPlayingAudio);
                break;

            case 'cursor':
                overlay.style.cursor = msg.cursor || 'default';
                break;

            case 'clipboard':
                clipText.value = msg.text;
                clipText.classList.remove('clip-glow-anim');
                void clipText.offsetWidth;
                clipText.classList.add('clip-glow-anim');
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(msg.text).catch(() => {});
                }
                break;

            case 'dialog':
                showDialogModal(msg.message, msg.dialogType, msg.defaultValue);
                break;

            case 'console_event':
                handleConsoleLog(msg);
                break;

            case 'network_event':
                handleNetworkLog(msg);
                break;

            case 'cookies_list':
                renderCookiesList(msg.cookies);
                break;

            case 'screenshot_taken':
                showScreenshotToast(msg.filename, msg.data);
                break;

            case 'auth_error':
                resetToLogin(msg.error || 'Session expired. Please log in again.');
                break;

            case 'error':
                if (msg.error) showOverlay(String(msg.error).slice(0, 200));
                break;

            case 'loading_state':
                handleLoadingState(msg.loading);
                break;

            case 'download_ready':
                addDownloadItem(msg.filename, msg.url);
                downloadsPanel.classList.remove('hidden');
                break;

            case 'file_chooser_open':
                localFileInput.multiple = !!msg.isMultiple;
                uploadPanel.classList.remove('hidden');
                break;

            case 'find_result':
                findCount.textContent = msg.count > 0 ? `${msg.count} match${msg.count > 1 ? 'es' : ''}` : 'No matches';
                break;
        }
    };
}

// ---------- Loading Progress & Overlay ----------
function handleLoadingState(loading) {
    if (loading) {
        clearTimeout(loadingTimer);
        loadingProgress.style.opacity = '1';
        loadingProgress.style.width = '0%';
        void loadingProgress.offsetWidth;
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

function showOverlay(text) {
    if (loadingText) loadingText.textContent = text || 'Loading...';
    loadingOverlay.classList.remove('hidden');
}

function hideOverlay() {
    loadingOverlay.classList.add('hidden');
}

function sendMsg(msg) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msg));
    }
}

// ---------- Tab Management ----------
const tabDomMap = new Map();

function renderTabs(tabs) {
    const seenIds = new Set();

    tabs.forEach(tab => {
        seenIds.add(tab.id);
        if (tab.isActive) {
            activeTabId = tab.id;
        }
        let tabEl = tabDomMap.get(tab.id);

        if (!tabEl) {
            tabEl = document.createElement('div');
            tabEl.dataset.tabId = tab.id;
            tabEl.setAttribute('role', 'tab');

            const iconEl = document.createElement('img');
            iconEl.className = 'tab-icon';
            iconEl.style.display = 'none';
            iconEl.onerror = () => { iconEl.style.display = 'none'; };

            const speakerEl = document.createElement('span');
            speakerEl.className = 'tab-speaker hidden';
            speakerEl.title = 'Tab is playing audio';
            speakerEl.textContent = '🔊';

            const titleEl = document.createElement('span');
            titleEl.className = 'tab-title';

            const closeBtn = document.createElement('button');
            closeBtn.className = 'tab-close';
            closeBtn.setAttribute('aria-label', 'Close tab');
            closeBtn.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';

            tabEl.appendChild(iconEl);
            tabEl.appendChild(speakerEl);
            tabEl.appendChild(titleEl);
            tabEl.appendChild(closeBtn);

            tabEl.addEventListener('click', () => {
                if (!tabEl.classList.contains('active')) {
                    showOverlay('Switching tab...');
                    viewportContainer.classList.remove('ready');
                    sendMsg({ type: 'switch_tab', tabId: tab.id });
                }
            });

            tabEl.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                contextTargetTabId = tab.id;
                showTabContextMenu(e.clientX, e.clientY);
            });

            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (tabEl.classList.contains('active') && tabs.length > 1) {
                    showOverlay('Closing tab...');
                }
                sendMsg({ type: 'close_tab', tabId: tab.id });
            });

            tabDomMap.set(tab.id, tabEl);
            tabsContainer.appendChild(tabEl);
        }

        const iconEl    = tabEl.querySelector('.tab-icon');
        const speakerEl = tabEl.querySelector('.tab-speaker');
        const titleEl   = tabEl.querySelector('.tab-title');

        const newTitle = tab.title || 'New Tab';
        if (titleEl.textContent !== newTitle) titleEl.textContent = newTitle;

        if (tab.favicon && iconEl.src !== tab.favicon) {
            iconEl.src = tab.favicon;
            iconEl.style.display = '';
        }

        if (tab.isPlayingAudio) {
            speakerEl.classList.remove('hidden');
        } else {
            speakerEl.classList.add('hidden');
        }

        const isActive = tab.isActive;
        tabEl.className = `tab${isActive ? ' active' : ''}`;
        tabEl.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    for (const [id, el] of tabDomMap) {
        if (!seenIds.has(id)) {
            el.remove();
            tabDomMap.delete(id);
        }
    }

    tabs.forEach(tab => {
        const el = tabDomMap.get(tab.id);
        if (el) tabsContainer.appendChild(el);
    });
}

function updateTabAudioIndicator(tabId, isPlaying) {
    const el = tabDomMap.get(tabId);
    if (el) {
        const speaker = el.querySelector('.tab-speaker');
        if (speaker) {
            if (isPlaying) speaker.classList.remove('hidden');
            else speaker.classList.add('hidden');
        }
    }
}

newTabBtn.addEventListener('click', () => sendMsg({ type: 'new_tab' }));

// ---------- Coordinate Mapping (Hardware Scaled Canvas) ----------
function getMappedCoords(clientX, clientY) {
    const rect = overlay.getBoundingClientRect();
    const scaleX = remoteWidth / rect.width;
    const scaleY = remoteHeight / rect.height;

    const x = Math.round((clientX - rect.left) * scaleX);
    const y = Math.round((clientY - rect.top) * scaleY);

    return {
        x: Math.max(0, Math.min(remoteWidth, x)),
        y: Math.max(0, Math.min(remoteHeight, y))
    };
}

const mapButton = (e) => ['left', 'middle', 'right'][e.button] ?? 'left';

let lastMoveTime = 0;
overlay.addEventListener('mousemove', (e) => {
    const now = performance.now();
    if (now - lastMoveTime < 30) return; // ~33fps mousemove cap
    lastMoveTime = now;
    const c = getMappedCoords(e.clientX, e.clientY);
    sendMsg({ type: 'mousemove', x: c.x, y: c.y });
});

overlay.addEventListener('mousedown', (e) => {
    e.preventDefault();
    viewportContainer.focus();
    const c = getMappedCoords(e.clientX, e.clientY);
    sendMsg({ type: 'mousedown', x: c.x, y: c.y, button: mapButton(e) });
});

overlay.addEventListener('mouseup', (e) => {
    const c = getMappedCoords(e.clientX, e.clientY);
    sendMsg({ type: 'mouseup', x: c.x, y: c.y, button: mapButton(e) });
});

overlay.addEventListener('contextmenu', (e) => e.preventDefault());

overlay.addEventListener('wheel', (e) => {
    e.preventDefault();
    sendMsg({ type: 'wheel', deltaX: e.deltaX, deltaY: e.deltaY });
}, { passive: false });

// Touch & Mobile Gesture Events
let activeTouch = false;
overlay.addEventListener('touchstart', (e) => {
    if (e.touches.length > 0) {
        activeTouch = true;
        const touch = e.touches[0];
        const c = getMappedCoords(touch.clientX, touch.clientY);
        sendMsg({ type: 'mousemove', x: c.x, y: c.y });
        sendMsg({ type: 'mousedown', x: c.x, y: c.y, button: 'left' });
    }
}, { passive: true });

overlay.addEventListener('touchmove', (e) => {
    if (activeTouch && e.touches.length > 0) {
        const now = performance.now();
        if (now - lastMoveTime < 30) return;
        lastMoveTime = now;
        const touch = e.touches[0];
        const c = getMappedCoords(touch.clientX, touch.clientY);
        sendMsg({ type: 'mousemove', x: c.x, y: c.y });
    }
}, { passive: true });

overlay.addEventListener('touchend', (e) => {
    if (activeTouch) {
        activeTouch = false;
        if (e.changedTouches.length > 0) {
            const touch = e.changedTouches[0];
            const c = getMappedCoords(touch.clientX, touch.clientY);
            sendMsg({ type: 'mouseup', x: c.x, y: c.y, button: 'left' });
        }
    }
}, { passive: true });

overlay.addEventListener('touchcancel', () => {
    activeTouch = false;
});

// ---------- Keyboard Management ----------
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
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
        if (e.key === 'Escape') {
            closeAllModals();
            viewportContainer.focus();
        }
        return;
    }

    if (e.key === 'Escape') {
        closeAllModals();
        return;
    }

    const isCmdOrCtrl = e.ctrlKey || e.metaKey;

    if (isCmdOrCtrl && e.shiftKey && e.key.toLowerCase() === 'i') {
        e.preventDefault();
        devtoolsBtn.click();
        return;
    }

    if (isCmdOrCtrl && e.shiftKey && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        historyBtn.click();
        return;
    }

    if (isCmdOrCtrl && !e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        urlInput.focus();
        urlInput.select();
        return;
    }

    if (isCmdOrCtrl && !e.shiftKey && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        historyBtn.click();
        return;
    }

    if (isCmdOrCtrl && e.key === '/') {
        e.preventDefault();
        shortcutsModal.classList.remove('hidden');
        return;
    }

    if (document.activeElement !== viewportContainer) return;

    if (isCmdOrCtrl && e.key.toLowerCase() === 'v') {
        e.preventDefault();
        if (navigator.clipboard && navigator.clipboard.readText) {
            navigator.clipboard.readText()
                .then(text => {
                    if (text) sendMsg({ type: 'type', text });
                })
                .catch(() => {
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
        if (activeTabId) sendMsg({ type: 'close_tab', tabId: activeTabId });
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
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) return;
    if (document.activeElement !== viewportContainer) return;
    sendMsg({ type: 'keyup', key: e.key, modifiers: getModifiers(e) });
});

window.addEventListener('paste', (e) => {
    if (document.activeElement !== viewportContainer) return;
    const text = e.clipboardData?.getData('text');
    if (text) sendMsg({ type: 'type', text });
});

// ---------- Omnibox & Navigation ----------
function navigate() {
    const input = urlInput.value.trim();
    if (!input) return;
    sendMsg({ type: 'goto', url: input, searchEngine: selectedSearchEngine });
    viewportContainer.focus();
}

goBtn.addEventListener('click', navigate);

urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')  { e.preventDefault(); navigate(); }
    if (e.key === 'Escape') { viewportContainer.focus(); }
});

urlInput.addEventListener('focus', () => urlInput.select());

backBtn.addEventListener('click', () => sendMsg({ type: 'back' }));
forwardBtn.addEventListener('click', () => sendMsg({ type: 'forward' }));
reloadBtn.addEventListener('click', () => sendMsg({ type: 'reload' }));

function updateSecurityBadge(url) {
    if (!url) return;
    try {
        const u = new URL(url);
        if (u.protocol === 'https:') {
            securityBadge.className = 'security-badge secure';
            securityBadgeText.textContent = 'Secure';
            secTransportVal.textContent = 'HTTPS TLS Isolated';
        } else if (u.protocol === 'http:') {
            securityBadge.className = 'security-badge insecure';
            securityBadgeText.textContent = 'Not Secure';
            secTransportVal.textContent = 'Plaintext HTTP (Isolated)';
        } else {
            securityBadge.className = 'security-badge internal';
            securityBadgeText.textContent = 'System';
            secTransportVal.textContent = 'Local Internal Buffer';
        }
    } catch {
        securityBadge.className = 'security-badge internal';
        securityBadgeText.textContent = 'Isolated';
    }
}

securityBadge.addEventListener('click', () => {
    secAdblockVal.textContent = adblockToggle.checked ? 'Active (Ghostery Filter)' : 'Disabled';
    securityModal.classList.remove('hidden');
});

securityCloseBtn.addEventListener('click', () => securityModal.classList.add('hidden'));

// Search Engine Selector
const ENGINE_ICONS = {
    google: '🔍',
    duckduckgo: '🦆',
    brave: '🦁',
    bing: '🌐',
    ecosia: '🌱'
};

searchEngineIcon.textContent = ENGINE_ICONS[selectedSearchEngine] || '🔍';

searchEngineBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    searchEngineMenu.classList.toggle('hidden');
    const rect = searchEngineBtn.getBoundingClientRect();
    searchEngineMenu.style.left = `${rect.left}px`;
    searchEngineMenu.style.top = `${rect.bottom + 6}px`;
});

document.querySelectorAll('#search-engine-menu .dropdown-item').forEach(btn => {
    btn.addEventListener('click', () => {
        selectedSearchEngine = btn.dataset.engine;
        localStorage.setItem('vb_search_engine', selectedSearchEngine);
        searchEngineIcon.textContent = ENGINE_ICONS[selectedSearchEngine] || '🔍';
        document.querySelectorAll('#search-engine-menu .dropdown-item').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        searchEngineMenu.classList.add('hidden');
        sendMsg({ type: 'set_search_engine', engine: selectedSearchEngine });
    });
});

// ---------- Page Tools & Device Emulation ----------
pageToolsBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    closeAllModals([pageToolsMenu]);
    pageToolsMenu.classList.toggle('hidden');
    const rect = pageToolsBtn.getBoundingClientRect();
    pageToolsMenu.style.left = `${rect.left - 100}px`;
    pageToolsMenu.style.top = `${rect.bottom + 6}px`;
});

deviceBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    closeAllModals([deviceMenu]);
    deviceMenu.classList.toggle('hidden');
    const rect = deviceBtn.getBoundingClientRect();
    deviceMenu.style.left = `${rect.left - 120}px`;
    deviceMenu.style.top = `${rect.bottom + 6}px`;
});

toolScreenshotView.addEventListener('click', () => {
    pageToolsMenu.classList.add('hidden');
    sendMsg({ type: 'capture_screenshot', fullPage: false });
});

toolScreenshotFull.addEventListener('click', () => {
    pageToolsMenu.classList.add('hidden');
    sendMsg({ type: 'capture_screenshot', fullPage: true });
});

toolExportPdf.addEventListener('click', () => {
    pageToolsMenu.classList.add('hidden');
    sendMsg({ type: 'export_pdf' });
});

toolInvertDark.addEventListener('click', () => {
    pageToolsMenu.classList.add('hidden');
    isDarkInverted = !isDarkInverted;
    canvas.style.filter = isDarkInverted ? 'invert(0.92) hue-rotate(180deg)' : 'none';
});

toolToggleHud.addEventListener('click', () => {
    pageToolsMenu.classList.add('hidden');
    perfHud.classList.toggle('hidden');
});

toolShortcuts.addEventListener('click', () => {
    pageToolsMenu.classList.add('hidden');
    shortcutsModal.classList.remove('hidden');
});

shortcutsCloseBtn.addEventListener('click', () => shortcutsModal.classList.add('hidden'));

// Device Presets
const DEVICE_RESOLUTIONS = {
    desktop: { width: 1920, height: 1080 },
    laptop: { width: 1366, height: 768 },
    tablet: { width: 1024, height: 1366 },
    iphone: { width: 393, height: 852 },
    galaxy: { width: 412, height: 915 }
};

document.querySelectorAll('#device-menu .dropdown-item').forEach(btn => {
    btn.addEventListener('click', () => {
        const dev = btn.dataset.device;
        document.querySelectorAll('#device-menu .dropdown-item').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        deviceMenu.classList.add('hidden');

        if (dev === 'match') {
            const vRect = viewportContainer.getBoundingClientRect();
            const w = Math.round(vRect.width);
            const h = Math.round(vRect.height);
            sendMsg({ type: 'set_viewport', width: w, height: h });
            showOverlay(`Matching window resolution (${w}x${h})...`);
        } else if (DEVICE_RESOLUTIONS[dev]) {
            const res = DEVICE_RESOLUTIONS[dev];
            sendMsg({ type: 'set_viewport', width: res.width, height: res.height });
            showOverlay(`Switching to ${dev} resolution (${res.width}x${res.height})...`);
        }
    });
});

// ---------- DevTools & Remote Console ----------
devtoolsBtn.addEventListener('click', () => {
    devtoolsDrawer.classList.toggle('hidden');
    if (!devtoolsDrawer.classList.contains('hidden')) {
        devtoolsBadge.classList.add('hidden');
        devtoolsBadge.textContent = '0';
    }
});

devtoolsCloseBtn.addEventListener('click', () => devtoolsDrawer.classList.add('hidden'));

devtoolsTabConsole.addEventListener('click', () => {
    devtoolsTabConsole.classList.add('active');
    devtoolsTabNetwork.classList.remove('active');
    devtoolsConsolePane.classList.remove('hidden');
    devtoolsNetworkPane.classList.add('hidden');
});

devtoolsTabNetwork.addEventListener('click', () => {
    devtoolsTabNetwork.classList.add('active');
    devtoolsTabConsole.classList.remove('active');
    devtoolsNetworkPane.classList.remove('hidden');
    devtoolsConsolePane.classList.add('hidden');
});

devtoolsClearBtn.addEventListener('click', () => {
    consoleEntries = [];
    networkEntries = [];
    consoleLogs.innerHTML = '<div class="console-empty">No console messages logged.</div>';
    networkLogs.innerHTML = '<div class="network-empty">No network requests recorded.</div>';
    consoleCount.textContent = '0';
    networkCount.textContent = '0';
});

function handleConsoleLog(msg) {
    const empty = consoleLogs.querySelector('.console-empty');
    if (empty) empty.remove();

    consoleEntries.push(msg);
    consoleCount.textContent = String(consoleEntries.length);

    if (devtoolsDrawer.classList.contains('hidden')) {
        devtoolsBadge.classList.remove('hidden');
        devtoolsBadge.textContent = String(Math.min(99, consoleEntries.length));
    }

    const row = document.createElement('div');
    row.className = `console-row ${msg.level || 'info'}`;

    const icon = document.createElement('span');
    icon.className = 'console-icon';
    icon.textContent = msg.level === 'error' ? '❌' : (msg.level === 'warn' ? '⚠️' : 'ℹ️');

    const text = document.createElement('span');
    text.className = 'console-text';
    text.textContent = msg.text || '';

    row.appendChild(icon);
    row.appendChild(text);
    consoleLogs.appendChild(row);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

function handleNetworkLog(msg) {
    const empty = networkLogs.querySelector('.network-empty');
    if (empty) empty.remove();

    networkEntries.push(msg);
    networkCount.textContent = String(networkEntries.length);

    const row = document.createElement('div');
    row.className = 'network-row';

    const status = document.createElement('span');
    status.className = `net-status ${msg.status < 400 ? 'status-ok' : 'status-err'}`;
    status.textContent = String(msg.status);

    const method = document.createElement('span');
    method.className = 'net-method';
    method.textContent = msg.method || 'GET';

    const url = document.createElement('span');
    url.className = 'net-url';
    url.title = msg.url;
    url.textContent = msg.url;

    row.appendChild(status);
    row.appendChild(method);
    row.appendChild(url);
    networkLogs.appendChild(row);
    networkLogs.scrollTop = networkLogs.scrollHeight;
}

// ---------- Browsing History ----------
function recordHistory(url) {
    if (!url || url === 'about:blank') return;
    try {
        let history = JSON.parse(localStorage.getItem('vb_history') || '[]');
        history = history.filter(h => h.url !== url);
        history.unshift({ url, title: url, ts: Date.now() });
        if (history.length > 200) history.pop();
        localStorage.setItem('vb_history', JSON.stringify(history));
    } catch (_) {}
}

historyBtn.addEventListener('click', () => {
    historyDrawer.classList.toggle('hidden');
    if (!historyDrawer.classList.contains('hidden')) {
        renderHistoryList();
    }
});

historyCloseBtn.addEventListener('click', () => historyDrawer.classList.add('hidden'));

historyClearBtn.addEventListener('click', () => {
    localStorage.removeItem('vb_history');
    renderHistoryList();
});

historySearchInput.addEventListener('input', () => {
    renderHistoryList(historySearchInput.value.trim().toLowerCase());
});

function renderHistoryList(filter = '') {
    historyList.innerHTML = '';
    const history = JSON.parse(localStorage.getItem('vb_history') || '[]');
    const filtered = filter ? history.filter(h => h.url.toLowerCase().includes(filter)) : history;

    if (filtered.length === 0) {
        historyList.innerHTML = '<div class="history-empty">No history found.</div>';
        return;
    }

    filtered.forEach(item => {
        const row = document.createElement('div');
        row.className = 'history-item';

        const urlSpan = document.createElement('span');
        urlSpan.className = 'history-url';
        urlSpan.title = item.url;
        urlSpan.textContent = item.url;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'history-time';
        timeSpan.textContent = new Date(item.ts).toLocaleTimeString();

        row.appendChild(urlSpan);
        row.appendChild(timeSpan);

        row.addEventListener('click', () => {
            urlInput.value = item.url;
            navigate();
            historyDrawer.classList.add('hidden');
        });

        historyList.appendChild(row);
    });
}

// ---------- Cookies Inspector ----------
viewCookiesBtn.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
    cookiesModal.classList.remove('hidden');
    cookiesList.innerHTML = '<p class="downloads-empty">Fetching session cookies...</p>';
    sendMsg({ type: 'get_cookies' });
});

cookiesCloseBtn.addEventListener('click', () => cookiesModal.classList.add('hidden'));

cookiesClearAllBtn.addEventListener('click', () => {
    if (confirm('Wipe all session cookies?')) {
        sendMsg({ type: 'clear_cookies' });
        cookiesModal.classList.add('hidden');
    }
});

function renderCookiesList(cookies) {
    cookiesList.innerHTML = '';
    if (!cookies || cookies.length === 0) {
        cookiesList.innerHTML = '<p class="downloads-empty">No active cookies found in this browser context.</p>';
        return;
    }

    const table = document.createElement('table');
    table.className = 'cookies-table';
    table.innerHTML = `
        <thead>
            <tr>
                <th>Domain</th>
                <th>Name</th>
                <th>Secure</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody></tbody>
    `;

    const tbody = table.querySelector('tbody');
    cookies.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${escapeHtml(c.domain)}</td>
            <td style="font-family: monospace;">${escapeHtml(c.name)}</td>
            <td>${c.secure ? '🔒 Yes' : 'No'}</td>
            <td><button class="btn-micro btn-danger">Wipe</button></td>
        `;
        tr.querySelector('button').addEventListener('click', () => {
            sendMsg({ type: 'clear_cookies', domain: c.domain });
            tr.remove();
        });
        tbody.appendChild(tr);
    });

    cookiesList.appendChild(table);
}

// ---------- Remote Dialog Modal (Alert, Confirm, Prompt) ----------
function showDialogModal(message, dialogType, defaultValue) {
    dialogTitle.textContent = dialogType === 'prompt' ? 'Website Prompt' : (dialogType === 'confirm' ? 'Confirm Action' : 'Website Message');
    dialogMessage.textContent = message || '';

    if (dialogType === 'prompt') {
        dialogInputGroup.classList.remove('hidden');
        dialogInput.value = defaultValue || '';
        dialogCancelBtn.classList.remove('hidden');
    } else if (dialogType === 'confirm') {
        dialogInputGroup.classList.add('hidden');
        dialogCancelBtn.classList.remove('hidden');
    } else {
        dialogInputGroup.classList.add('hidden');
        dialogCancelBtn.classList.add('hidden');
    }

    dialogModal.classList.remove('hidden');
    if (dialogType === 'prompt') {
        dialogInput.focus();
        dialogInput.select();
    } else {
        dialogOkBtn.focus();
    }
}

dialogOkBtn.addEventListener('click', () => {
    const promptText = dialogInput.value;
    dialogModal.classList.add('hidden');
    sendMsg({ type: 'dialog_response', accept: true, promptText });
    viewportContainer.focus();
});

dialogCancelBtn.addEventListener('click', () => {
    dialogModal.classList.add('hidden');
    sendMsg({ type: 'dialog_response', accept: false });
    viewportContainer.focus();
});

dialogInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') dialogOkBtn.click();
    if (e.key === 'Escape') dialogCancelBtn.click();
});

// ---------- Screenshot Toast ----------
function showScreenshotToast(filename, base64Data) {
    const toast = document.createElement('div');
    toast.className = 'screenshot-toast';
    toast.innerHTML = `
        <img src="data:image/png;base64,${base64Data}" alt="Captured Screenshot" class="toast-thumb" />
        <div class="toast-body">
            <strong>Screenshot Saved</strong>
            <span>${escapeHtml(filename)}</span>
        </div>
        <button class="btn-micro" id="toast-close">✕</button>
    `;
    document.body.appendChild(toast);
    toast.querySelector('#toast-close').addEventListener('click', () => toast.remove());
    setTimeout(() => toast.remove(), 6000);
}

// ---------- Clipboard Manager ----------
clipBtn.addEventListener('click', () => {
    clipModal.classList.toggle('hidden');
    if (!clipModal.classList.contains('hidden')) {
        closeAllModals([clipModal]);
        clipText.focus();
        clipText.select();
    }
});

clipCloseBtn.addEventListener('click', () => clipModal.classList.add('hidden'));

clipPushBtn.addEventListener('click', () => {
    const text = clipText.value;
    if (text) {
        sendMsg({ type: 'type', text });
        clipModal.classList.add('hidden');
        viewportContainer.focus();
    }
});

// ---------- Session Settings Modal ----------
settingsBtn.addEventListener('click', () => {
    settingsModal.classList.toggle('hidden');
    if (!settingsModal.classList.contains('hidden')) {
        closeAllModals([settingsModal]);
    }
});

settingsCloseBtn.addEventListener('click', () => settingsModal.classList.add('hidden'));

adblockToggle.addEventListener('change', () => {
    sendMsg({ type: 'toggle_adblocker', enabled: adblockToggle.checked });
});

vpnToggle.addEventListener('change', () => {
    const enabled = vpnToggle.checked;
    sendMsg({ type: 'toggle_vpn', enabled });
    showOverlay(enabled ? '⚡ Connecting to Cloudflare WARP VPN...' : '🔓 Disconnecting from WARP VPN...');
    settingsModal.classList.add('hidden');
});

proxyApplyBtn.addEventListener('click', () => {
    const proxy = proxyInput.value.trim();
    if (!proxy) return;
    sendMsg({ type: 'set_proxy', proxy });
    showOverlay('Applying proxy & restarting browser context...');
    settingsModal.classList.add('hidden');
});

proxyClearBtn.addEventListener('click', () => {
    proxyInput.value = '';
    sendMsg({ type: 'set_proxy', proxy: '' });
    showOverlay('Clearing proxy & restarting browser context...');
    settingsModal.classList.add('hidden');
});

proxyInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') proxyApplyBtn.click();
});

// Zoom Controls
function applyZoom(level) {
    zoomLevel = Math.min(5.0, Math.max(0.2, level));
    zoomDisplay.textContent = Math.round(zoomLevel * 100) + '%';
    sendMsg({ type: 'set_zoom', zoom: zoomLevel });
}

zoomInBtn.addEventListener('click', () => applyZoom(zoomLevel + 0.1));
zoomOutBtn.addEventListener('click', () => applyZoom(zoomLevel - 0.1));
zoomResetBtn.addEventListener('click', () => applyZoom(1.0));

// Mute Toggle
muteBtn.addEventListener('click', () => {
    isMuted = !isMuted;
    sendMsg({ type: 'set_mute', muted: isMuted });
    muteIconOn.style.display = isMuted ? 'none' : '';
    muteIconOff.style.display = isMuted ? '' : 'none';
    muteBtn.title = isMuted ? 'Unmute Tab' : 'Mute Tab';
});

// User-Agent Selection
uaSelect.addEventListener('change', () => {
    const val = uaSelect.value;
    if (val === 'custom') {
        customUaInput.classList.remove('hidden');
        customUaInput.focus();
    } else {
        customUaInput.classList.add('hidden');
        sendMsg({ type: 'set_useragent', userAgent: val });
        showOverlay('Updating User-Agent profile...');
    }
});

customUaInput.addEventListener('blur', () => {
    const ua = customUaInput.value.trim();
    if (ua) {
        sendMsg({ type: 'set_useragent', userAgent: ua });
        showOverlay('Updating custom User-Agent...');
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

// ---------- Find in Page ----------
findBtn.addEventListener('click', () => {
    findBar.classList.toggle('hidden');
    if (!findBar.classList.contains('hidden')) {
        closeAllModals([findBar]);
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
    viewportContainer.focus();
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

// ---------- Downloads Drawer ----------
downloadsBtn.addEventListener('click', () => {
    downloadsPanel.classList.toggle('hidden');
    if (!downloadsPanel.classList.contains('hidden')) {
        closeAllModals([downloadsPanel]);
    }
});

downloadsCloseBtn.addEventListener('click', () => downloadsPanel.classList.add('hidden'));

function addDownloadItem(filename, url) {
    const empty = downloadsList.querySelector('.downloads-empty');
    if (empty) empty.remove();

    const safeName = String(filename || 'download').slice(0, 180);
    let safeUrl = String(url || '');
    try {
        const parsed = new URL(safeUrl, location.origin);
        if (parsed.origin !== location.origin || !parsed.pathname.startsWith('/downloads/')) {
            safeUrl = '#';
        } else {
            safeUrl = parsed.pathname + parsed.search;
        }
    } catch {
        safeUrl = '#';
    }

    const item = document.createElement('div');
    item.className = 'download-item';

    const nameEl = document.createElement('span');
    nameEl.className = 'download-item-name';
    nameEl.title = safeName;
    nameEl.textContent = safeName;

    const linkEl = document.createElement('a');
    linkEl.className = 'download-item-link';
    linkEl.href = safeUrl;
    linkEl.download = safeName;
    linkEl.textContent = 'Save ↓';

    item.appendChild(nameEl);
    item.appendChild(linkEl);
    downloadsList.prepend(item);
}

// ---------- Multi-File Upload Modal ----------
uploadPickBtn.addEventListener('click', () => localFileInput.click());

localFileInput.addEventListener('change', () => {
    const files = localFileInput.files;
    if (!files || files.length === 0) return;
    uploadFilename.textContent = files.length === 1 ? files[0].name : `${files.length} files selected`;
    uploadSendBtn.disabled = false;
});

uploadSendBtn.addEventListener('click', () => {
    const files = localFileInput.files;
    if (!files || files.length === 0) return;

    const MAX_UPLOAD = 16 * 1024 * 1024;
    const readers = [];
    const payloads = [];

    Array.from(files).forEach(file => {
        if (file.size > MAX_UPLOAD) return;
        const p = new Promise(resolve => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const base64 = e.target.result.split(',')[1];
                payloads.push({ name: file.name, data: base64 });
                resolve();
            };
            reader.readAsDataURL(file);
        });
        readers.push(p);
    });

    Promise.all(readers).then(() => {
        if (payloads.length > 0) {
            sendMsg({ type: 'files_uploaded', files: payloads });
        }
        cancelUpload();
    });
});

function cancelUpload() {
    uploadPanel.classList.add('hidden');
    localFileInput.value = '';
    uploadFilename.textContent = 'No files chosen';
    uploadSendBtn.disabled = true;
    sendMsg({ type: 'file_chooser_cancel' });
}

uploadCancelBtn.addEventListener('click', cancelUpload);
uploadCloseBtn.addEventListener('click', cancelUpload);

// ---------- Stream Performance Quality ----------
qualitySelect.addEventListener('change', () => {
    const val = qualitySelect.value;
    if (val === 'png') {
        sendMsg({ type: 'set_stream_quality', format: 'png' });
    } else if (val === 'jpeg_98') {
        sendMsg({ type: 'set_stream_quality', format: 'jpeg', quality: 98 });
    } else if (val === 'jpeg_90') {
        sendMsg({ type: 'set_stream_quality', format: 'jpeg', quality: 90 });
    } else {
        sendMsg({ type: 'set_stream_quality', format: 'jpeg', quality: 80 });
    }
});

// ---------- Bookmarks Bar ----------
const DEFAULT_BOOKMARKS = [
    { name: 'Google', url: 'https://www.google.com' },
    { name: 'GitHub', url: 'https://github.com' },
    { name: 'Debian', url: 'https://www.debian.org' },
    { name: 'DuckDuckGo', url: 'https://duckduckgo.com' }
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

        const icon = document.createElement('img');
        icon.className = 'bookmark-item-icon';

        let domain = bm.url;
        try { domain = new URL(bm.url).hostname; } catch (_) {}
        icon.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=16`;
        icon.onerror = () => { icon.style.display = 'none'; };

        const nameSpan = document.createElement('span');
        nameSpan.textContent = bm.name;

        item.appendChild(icon);
        item.appendChild(nameSpan);

        item.addEventListener('click', () => {
            urlInput.value = bm.url;
            navigate();
        });

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
    if (name === null) return;

    bookmarks.push({ name: name.trim() || hostname, url: targetUrl });
    saveBookmarks();
    renderBookmarks();
});

loadBookmarks();

// ---------- Context Menus ----------
overlay.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    closeAllModals([contextMenu]);
    contextMenu.classList.remove('hidden');

    const menuW = 190;
    const menuH = 240;
    let x = e.clientX;
    let y = e.clientY;

    if (x + menuW > window.innerWidth) x = window.innerWidth - menuW - 10;
    if (y + menuH > window.innerHeight) y = window.innerHeight - menuH - 10;

    contextMenu.style.left = `${x}px`;
    contextMenu.style.top = `${y}px`;
});

function showTabContextMenu(clientX, clientY) {
    closeAllModals([tabContextMenu]);
    tabContextMenu.classList.remove('hidden');

    const menuW = 180;
    const menuH = 180;
    let x = clientX;
    let y = clientY;

    if (x + menuW > window.innerWidth) x = window.innerWidth - menuW - 10;
    if (y + menuH > window.innerHeight) y = window.innerHeight - menuH - 10;

    tabContextMenu.style.left = `${x}px`;
    tabContextMenu.style.top = `${y}px`;
}

document.addEventListener('click', (e) => {
    if (!contextMenu.contains(e.target)) contextMenu.classList.add('hidden');
    if (!tabContextMenu.contains(e.target)) tabContextMenu.classList.add('hidden');
    if (!searchEngineMenu.contains(e.target) && e.target !== searchEngineBtn && !searchEngineBtn.contains(e.target)) {
        searchEngineMenu.classList.add('hidden');
    }
    if (!pageToolsMenu.contains(e.target) && e.target !== pageToolsBtn && !pageToolsBtn.contains(e.target)) {
        pageToolsMenu.classList.add('hidden');
    }
    if (!deviceMenu.contains(e.target) && e.target !== deviceBtn && !deviceBtn.contains(e.target)) {
        deviceMenu.classList.add('hidden');
    }
});

// Viewport Context Menu Actions
ctxBack.addEventListener('click', () => sendMsg({ type: 'back' }));
ctxForward.addEventListener('click', () => sendMsg({ type: 'forward' }));
ctxReload.addEventListener('click', () => sendMsg({ type: 'reload' }));
ctxNewTab.addEventListener('click', () => sendMsg({ type: 'new_tab' }));
ctxDuplicate.addEventListener('click', () => {
    if (activeTabId) sendMsg({ type: 'duplicate_tab', tabId: activeTabId });
});
ctxScreenshot.addEventListener('click', () => {
    sendMsg({ type: 'capture_screenshot', fullPage: false });
});
ctxAdblock.addEventListener('click', () => {
    adblockToggle.checked = !adblockToggle.checked;
    sendMsg({ type: 'toggle_adblocker', enabled: adblockToggle.checked });
});
ctxClear.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear session cookies, permissions, and cache?')) {
        sendMsg({ type: 'clear_session' });
    }
});

// Tab Context Menu Actions
tabCtxReload.addEventListener('click', () => {
    if (contextTargetTabId) sendMsg({ type: 'reload_tab', tabId: contextTargetTabId });
});
tabCtxDuplicate.addEventListener('click', () => {
    if (contextTargetTabId) sendMsg({ type: 'duplicate_tab', tabId: contextTargetTabId });
});
tabCtxMute.addEventListener('click', () => {
    if (contextTargetTabId) sendMsg({ type: 'mute_tab', tabId: contextTargetTabId, muted: true });
});
tabCtxClose.addEventListener('click', () => {
    if (contextTargetTabId) sendMsg({ type: 'close_tab', tabId: contextTargetTabId });
});
tabCtxCloseOthers.addEventListener('click', () => {
    if (contextTargetTabId) sendMsg({ type: 'close_other_tabs', tabId: contextTargetTabId });
});

// ---------- Window Controls ----------
if (winMinimize) {
    winMinimize.addEventListener('click', () => {
        resetToLogin();
        passwordInput.focus();
    });
}
if (winMaximize) {
    winMaximize.addEventListener('click', () => {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(() => {});
        } else {
            document.exitFullscreen().catch(() => {});
        }
    });
}
if (winClose) {
    winClose.addEventListener('click', () => {
        if (confirm('Disconnect from current remote browser session?')) {
            resetToLogin();
            passwordInput.value = '';
        }
    });
}

function closeAllModals(except = []) {
    const list = [
        settingsModal, clipModal, downloadsPanel, uploadPanel, findBar,
        contextMenu, tabContextMenu, searchEngineMenu, pageToolsMenu,
        deviceMenu, historyDrawer, securityModal, shortcutsModal, cookiesModal
    ];
    list.forEach(m => {
        if (m && !except.includes(m)) m.classList.add('hidden');
    });
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ---------- Bootstrap Stored Session ----------
(async () => {
    try {
        const res = await fetch('/api/session', { credentials: 'same-origin' });
        if (!res.ok) {
            sessionStorage.removeItem('vb_token');
            return;
        }
        sessionStorage.setItem('vb_token', '1');
        loginScreen.classList.add('hidden');
        appContainer.classList.remove('hidden');
        initApp();
    } catch (_) {
        sessionStorage.removeItem('vb_token');
    }
})();
