// Current realtime socket id (set by app.js once connected). Sent on writes so
// the server can tell collaborators apart from the author of a change.
let SOCKET_ID = null;

// Read a cookie value by name (used for the double-submit CSRF token).
function readCookie(name) {
  for (const c of document.cookie.split('; ')) {
    const i = c.indexOf('=');
    if (i !== -1 && c.slice(0, i) === name) return decodeURIComponent(c.slice(i + 1));
  }
  return null;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Thin wrapper around fetch for the JSON API. Cookies carry the session.
const api = {
  async request(method, url, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    };
    if (SOCKET_ID) opts.headers['x-socket-id'] = SOCKET_ID;
    // Echo the CSRF cookie back in a header on state-changing requests so the
    // server's double-submit check passes (the cookie is set on page load).
    if (MUTATING_METHODS.has(method)) {
      const csrf = readCookie('csrf');
      if (csrf) opts.headers['X-CSRF-Token'] = csrf;
    }
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }
    // Session gone (expired, revoked, logged out elsewhere) on a page that
    // requires one: leave immediately instead of rendering a half-broken UI.
    if (res.status === 401 && isPrivatePage()) {
      redirectToLogin();
      throw Object.assign(new Error('Session expirée'), { status: 401 });
    }
    if (!res.ok) {
      const message = (data && data.error) || `Erreur ${res.status}`;
      const err = new Error(message);
      err.status = res.status;
      throw err;
    }
    return data;
  },
  get(url) { return this.request('GET', url); },
  post(url, body) { return this.request('POST', url, body); },
  patch(url, body) { return this.request('PATCH', url, body); },
  del(url) { return this.request('DELETE', url); },
};

// ---- Session guard for authenticated pages ----
// Authenticated pages are only served to a valid session (see server.js), and
// mark themselves with <body data-auth="required">. Their content stays hidden
// (CSS: body[data-auth="required"]:not(.auth-ok)) until the page script has
// confirmed the session with /api/auth/me and called markAuthenticated().
function isPrivatePage() {
  return document.body && document.body.dataset.auth === 'required';
}

function redirectToLogin() {
  const next = window.location.pathname + window.location.search;
  window.location.replace('/login?next=' + encodeURIComponent(next));
}

function markAuthenticated() {
  document.body.classList.add('auth-ok');
}

// A page restored from the back/forward cache skips the server check — e.g.
// pressing Back after logging out. Re-validate the session before showing it.
window.addEventListener('pageshow', (e) => {
  if (!e.persisted || !isPrivatePage()) return;
  document.body.classList.remove('auth-ok');
  fetch('/api/auth/me', { credentials: 'same-origin', cache: 'no-store' })
    .then((r) => { if (r.ok) markAuthenticated(); else redirectToLogin(); })
    .catch(redirectToLogin);
});

// Small helpers shared by pages
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toast(msg) {
  let el = document.querySelector('.toast');
  if (!el) {
    el = document.createElement('div');
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2500);
}

// ---- Theme (light / dark) — shared across all pages ----
// Apply the saved theme as early as possible to limit flashing.
(function () {
  const saved = localStorage.getItem('theme');
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
})();

function currentTheme() {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
}

function syncThemeButtons() {
  const label = currentTheme() === 'light' ? '🌙' : '☀️';
  document.querySelectorAll('.theme-toggle').forEach((b) => { b.textContent = label; });
}

function toggleTheme() {
  const next = currentTheme() === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('theme', next);
  syncThemeButtons();
}

document.addEventListener('DOMContentLoaded', () => {
  syncThemeButtons();
  document.querySelectorAll('.theme-toggle').forEach((b) => b.addEventListener('click', toggleTheme));
});
