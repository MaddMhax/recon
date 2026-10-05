require('dotenv').config();
require('./lib/asyncErrors'); // before any router is built
const path = require('path');
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');

const { connectDB } = require('./config/db');
const { runSeed } = require('./seed');
const { initRealtime } = require('./realtime');
const { issueCsrfToken, requireCsrf, cookieSecure } = require('./middleware/csrf');
const { resolveSession } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/users');
const referentialRoutes = require('./routes/referentials');

// Refuse to run with a guessable signing secret: anyone knowing it can forge a
// session cookie for any account, admin included.
const KNOWN_SECRETS = ['please-change-this-secret', 'change-this-to-a-long-random-string'];
const secret = process.env.JWT_SECRET || '';
if (secret.length < 32 || KNOWN_SECRETS.includes(secret)) {
  const msg = '[security] JWT_SECRET is missing, a known default, or shorter than 32 characters. ' +
    'Generate one with: openssl rand -hex 32';
  if (process.env.NODE_ENV === 'production') {
    console.error(msg);
    process.exit(1);
  }
  console.warn(msg + ' (allowed outside production only)');
}

const app = express();
app.disable('x-powered-by');

// Only trust X-Forwarded-* when a reverse proxy is actually in front (set
// TRUST_PROXY, e.g. "1" for one hop). Trusting it on a directly exposed port
// would let any client spoof its IP and dodge the login rate limit.
const trustProxy = process.env.TRUST_PROXY;
if (trustProxy && !/^(0|false|no)$/i.test(trustProxy)) {
  app.set('trust proxy', /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);
}

app.use(express.json({ limit: '5mb' })); // generous for JSON catalog imports
app.use(cookieParser());

// Security headers (applied to every response).
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  // Defense-in-depth CSP. No inline/remote scripts; same-origin only. Inline
  // styles and data: images are needed (avatar previews, dynamic chip colors).
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join('; ')
  );
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (cookieSecure()) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// CSRF: hand every client a double-submit token cookie, then require a matching
// X-CSRF-Token header on all state-changing requests (skips GET/HEAD/OPTIONS, so
// static assets and page loads are unaffected). Mounted before the routes so it
// guards every POST/PUT/PATCH/DELETE in the app.
app.use(issueCsrfToken);
app.use(requireCsrf);

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/referentials', referentialRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* ------------------------------------------------------------------ */
/* Frontend                                                            */
/* ------------------------------------------------------------------ */
// frontend/public  — login, password reset, CSS/fonts and the minimal scripts
//                    those pages need. Served to anyone.
// frontend/private — the application itself (pages + scripts). Default-deny:
//                    nothing in it is reachable except through the explicit,
//                    session-checked routes below, so neither the pages nor
//                    their source code load before authentication.
const publicDir = path.join(__dirname, '..', 'frontend', 'public');
const privateDir = path.join(__dirname, '..', 'frontend', 'private');

// Authenticated content must never be stored by the browser or a proxy: after
// logout, Back must not show it from cache.
const noStore = (res) => res.setHeader('Cache-Control', 'no-store');

// Session check for page and script requests. Unauthenticated page requests
// are redirected to /login (keeping where they wanted to go); script requests
// get a bare 404, so their existence is not even revealed.
function gate({ admin = false, page = true } = {}) {
  return async (req, res, next) => {
    const user = await resolveSession(req.cookies && req.cookies.token);
    if (user && (!admin || user.role === 'admin')) {
      req.user = user;
      noStore(res);
      return next();
    }
    if (!page) return res.status(404).end();
    if (user) return res.redirect(302, '/'); // signed in, but not an admin
    const next_ = req.originalUrl === '/' ? '' : '?next=' + encodeURIComponent(req.path);
    return res.redirect(302, '/login' + next_);
  };
}

const sendPrivate = (file) => (_req, res) => res.sendFile(path.join(privateDir, file));

// Pages
app.get('/', gate(), sendPrivate('app.html'));
// Project share links (/p/<slug>) are client-side routes; serve the app shell so
// the link works on a fresh load/refresh. app.js reads the slug and opens it.
app.get('/p/:slug([0-9a-fA-F]{16})', gate(), sendPrivate('app.html'));
app.get('/profile', gate(), sendPrivate('profile.html'));
app.get('/admin', gate({ admin: true }), sendPrivate('admin.html'));

// Application scripts (explicit allow-list; admin.js for admins only).
const PRIVATE_SCRIPTS = { 'app.js': {}, 'profile.js': {}, 'profile-page.js': {}, 'admin.js': { admin: true } };
app.get('/js/:file', (req, res, next) => {
  const opts = PRIVATE_SCRIPTS[req.params.file];
  if (!opts) return next(); // maybe a public script
  return gate({ ...opts, page: false })(req, res, () =>
    res.sendFile(path.join(privateDir, 'js', req.params.file)));
});

// Public pages. A visitor who is already signed in skips the login form.
app.get('/login', async (req, res) => {
  if (await resolveSession(req.cookies && req.cookies.token)) return res.redirect(302, '/');
  noStore(res);
  res.sendFile(path.join(publicDir, 'login.html'));
});
app.get('/reset', (_req, res) => {
  noStore(res);
  res.sendFile(path.join(publicDir, 'reset.html'));
});

// Old direct file URLs → their routes (bookmarks keep working, files never served raw).
app.get(['/index.html', '/app.html'], (_req, res) => res.redirect(301, '/'));
app.get(['/admin.html', '/profile.html', '/login.html', '/reset.html'], (req, res) =>
  res.redirect(301, req.path.replace(/\.html$/, '')));

app.use(express.static(publicDir, { index: false, redirect: false }));

// Anything else: plain 404 (no directory listing, no SPA fallback).
app.use((_req, res) => res.status(404).type('text/plain').send('Not found'));

// Central error handler
app.use((err, _req, res, _next) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

const PORT = process.env.PORT || 3000;

// Wrap Express in an HTTP server so Socket.IO can share the same port, and
// expose `io` to the routes (via app.get('io')) for live broadcasts.
const server = http.createServer(app);
const io = initRealtime(server);
app.set('io', io);

(async () => {
  try {
    await connectDB();
    await runSeed();
    server.listen(PORT, () => console.log(`[server] listening on port ${PORT}`));
  } catch (err) {
    console.error('[server] failed to start:', err);
    process.exit(1);
  }
})();
