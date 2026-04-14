/**
 * AegisCrypt — Frontend JavaScript
 * Auth, API calls, polling, Chart.js helpers
 */

const API_BASE = window.location.origin + '/api';

// ─── Auth Helpers ───

function getToken() {
    return localStorage.getItem('ss_token');
}

function setToken(token) {
    localStorage.setItem('ss_token', token);
}

function getUser() {
    const u = localStorage.getItem('ss_user');
    return u ? JSON.parse(u) : null;
}

function setUser(user) {
    localStorage.setItem('ss_user', JSON.stringify(user));
}

function logout() {
    apiFetch('/auth/logout', { method: 'POST' }).finally(() => {
        localStorage.removeItem('ss_token');
        localStorage.removeItem('ss_user');
        window.location.href = '/';
    });
}

function requireAuth() {
    if (!getToken()) {
        window.location.href = '/';
        return false;
    }
    return true;
}

// ─── API Fetch Wrapper ───

async function apiFetch(endpoint, options = {}) {
    const url = API_BASE + endpoint;
    const headers = options.headers || {};
    const token = getToken();
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    if (!(options.body instanceof FormData)) {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    }
    const resp = await fetch(url, { ...options, headers });
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401 && data.code === 'token_expired') {
        localStorage.removeItem('ss_token');
        window.location.href = '/';
        return null;
    }
    if (!resp.ok) {
        throw { status: resp.status, ...data };
    }
    return data;
}

// ─── Notification Bell ───

let alertPollTimer = null;

function startAlertPolling() {
    updateAlertBadge();
    alertPollTimer = setInterval(updateAlertBadge, 10000);
}

async function updateAlertBadge() {
    try {
        const data = await apiFetch('/alerts');
        const unresolved = data.alerts.filter(a => !a.resolved).length;
        const badge = document.getElementById('notif-count');
        if (badge) {
            badge.textContent = unresolved;
            badge.style.display = unresolved > 0 ? 'flex' : 'none';
        }
    } catch (e) { /* silent */ }
}

// ─── Toast Notifications ───

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    const colors = {
        info: 'border-blue-500 bg-blue-500/10',
        success: 'border-green-500 bg-green-500/10',
        error: 'border-red-500 bg-red-500/10',
        warning: 'border-yellow-500 bg-yellow-500/10',
    };
    toast.className = `border-l-4 p-4 rounded-r-lg mb-2 ${colors[type] || colors.info} text-white text-sm transition-all`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function createToastContainer() {
    const c = document.createElement('div');
    c.id = 'toast-container';
    c.className = 'fixed top-4 right-4 z-50 w-80';
    document.body.appendChild(c);
    return c;
}

// ─── Sidebar Active Link ───

function setActiveLink() {
    const path = window.location.pathname;
    document.querySelectorAll('.sidebar-link').forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === path);
    });
}

// ─── On Load ───

document.addEventListener('DOMContentLoaded', () => {
    setActiveLink();
    if (getToken() && document.getElementById('notif-count')) {
        startAlertPolling();
    }
    // Display username
    const userEl = document.getElementById('user-display');
    const user = getUser();
    if (userEl && user) {
        userEl.textContent = user.username;
    }
});

// ─── Admin Triggers ───

async function triggerModelRetrain(btnElement) {
    if (btnElement) {
        btnElement.disabled = true;
        const originalText = btnElement.innerHTML;
        btnElement.innerHTML = `<svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Retraining...`;
    }

    try {
        const data = await apiFetch('/alerts/retrain', { method: 'POST' });
        showToast(`✅ Model retrained using ${data.records_used} records.`, 'success');
    } catch (e) {
        console.error('Retrain error:', e);
        showToast(`❌ Failed to retrain mode: ${e.message || e.error || 'Unknown error'}`, 'error');
    } finally {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.innerHTML = `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Retrain Model
            `;
        }
    }
}
