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

// ---- SSO provider logos (inline SVG, shared by login + admin pages) ----
const SSO_LOGOS = {
  google: '<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>',
  github: '<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
  gitlab: '<svg width="18" height="18" viewBox="0 0 24 24" fill="#FC6D26" aria-hidden="true"><path d="M23.6 9.6l-.03-.08-3.26-8.5a.85.85 0 0 0-1.62.09L16.5 7.9H7.5L5.31 1.11a.85.85 0 0 0-1.62-.09L.43 9.52.4 9.6a6.05 6.05 0 0 0 2 6.98l.04.03 4.96 3.71 2.45 1.86 1.5 1.13a1 1 0 0 0 1.22 0l1.5-1.13 2.45-1.86 4.99-3.73.03-.02a6.05 6.05 0 0 0 2.04-6.98z"/></svg>',
  keycloak: '<svg width="18" height="18" viewBox="0 0 24 24" fill="#33AED9" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 11 4.6-2.3 8-6 8-11V5l-8-3zm0 2.2 6 2.25V11c0 3.9-2.5 6.9-6 8.8-3.5-1.9-6-4.9-6-8.8V6.45L12 4.2z"/></svg>',
  microsoft: '<svg width="18" height="18" viewBox="0 0 23 23" aria-hidden="true"><path fill="#F25022" d="M1 1h10v10H1z"/><path fill="#7FBA00" d="M12 1h10v10H12z"/><path fill="#00A4EF" d="M1 12h10v10H1z"/><path fill="#FFB900" d="M12 12h10v10H12z"/></svg>',
  custom: '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21 10h-8.35A5.99 5.99 0 0 0 7 6a6 6 0 1 0 5.65 8H13l2 2 2-2 2 2 3-3-1-2zm-14 4a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"/></svg>',
};
function ssoLogo(provider) { return SSO_LOGOS[provider] || SSO_LOGOS.custom; }

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
