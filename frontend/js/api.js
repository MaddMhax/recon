// Current realtime socket id (set by app.js once connected). Sent on writes so
// the server can tell collaborators apart from the author of a change.
let SOCKET_ID = null;

// Thin wrapper around fetch for the JSON API. Cookies carry the session.
const api = {
  async request(method, url, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    };
    if (SOCKET_ID) opts.headers['x-socket-id'] = SOCKET_ID;
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }
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

// Small helpers shared by pages
const PROJECT_STATUS_LABELS = {
  planning: 'Cadrage',
  active: 'En cours',
  reporting: 'Rédaction',
  completed: 'Terminé',
  archived: 'Archivé',
};

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
