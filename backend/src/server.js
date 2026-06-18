require('dotenv').config();
const path = require('path');
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');

const { connectDB } = require('./config/db');
const { runSeed } = require('./seed');
const { initRealtime } = require('./realtime');
const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/users');

const app = express();

// Behind a reverse proxy (HTTPS terminator), trust X-Forwarded-* so the
// Secure-cookie / protocol detection behaves correctly.
app.set('trust proxy', 1);

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
  next();
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Static frontend
const frontendDir = path.join(__dirname, '..', 'frontend');

// Convenience aliases so the documented "/admin" path works (the file is
// served by express.static at /admin.html, but not at /admin).
app.get('/admin', (_req, res) => res.sendFile(path.join(frontendDir, 'admin.html')));
app.get('/reset', (_req, res) => res.sendFile(path.join(frontendDir, 'reset.html')));

app.use(express.static(frontendDir));

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
