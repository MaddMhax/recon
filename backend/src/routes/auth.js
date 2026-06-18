const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { getSsoConfig } = require('../models/SsoConfig');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');

const MAX_AVATAR_BYTES = 2 * 1024 * 1024; // 2 MB

// Strictly parse a data URL into validated PNG/JPEG bytes. Returns null if the
// MIME is not allowed OR the magic bytes don't match the declared MIME (this
// rejects SVG, HTML/JS polyglots and spoofed content-types).
function parseDataUrlImage(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const m = dataUrl.match(/^data:(image\/png|image\/jpeg);base64,([A-Za-z0-9+/=]+)$/);
  if (!m) return null;
  const contentType = m[1];
  let data;
  try {
    data = Buffer.from(m[2], 'base64');
  } catch (_) {
    return null;
  }
  if (!data || data.length < 4) return null;
  const isPng = data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4e && data[3] === 0x47 &&
    data[4] === 0x0d && data[5] === 0x0a && data[6] === 0x1a && data[7] === 0x0a;
  const isJpeg = data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
  if (contentType === 'image/png' && !isPng) return null;
  if (contentType === 'image/jpeg' && !isJpeg) return null;
  if (!isPng && !isJpeg) return null;
  return { contentType, data };
}

// Find a user by a still-valid reset token (returns null otherwise).
async function findByValidResetToken(token) {
  if (!token) return null;
  const user = await User.findOne({ where: { resetTokenHash: hashToken(token) } });
  if (!user || !user.resetTokenExpires || new Date(user.resetTokenExpires).getTime() < Date.now()) return null;
  return user;
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '12h' }
  );
}

// The `Secure` flag tells the browser to send the cookie only over HTTPS.
// Tying it to NODE_ENV alone breaks plain-HTTP deployments (e.g. running the
// container over http://localhost): the browser silently drops the Secure
// cookie, so the SPA looks logged in (it reuses the user object returned by
// /login) but the very next full page load — like opening /admin — has no
// cookie, gets a 401 from /api/auth/me and bounces back to the login screen.
//
// Default: secure in production, but allow an explicit override so the app
// works over HTTP when no TLS terminator is in front of it. Set
// COOKIE_SECURE=true once you serve over HTTPS (directly or behind a proxy).
function cookieSecure() {
  if (process.env.COOKIE_SECURE !== undefined) {
    return /^(1|true|yes)$/i.test(process.env.COOKIE_SECURE);
  }
  return process.env.NODE_ENV === 'production';
}

function setAuthCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: cookieSecure(),
    maxAge: 12 * 60 * 60 * 1000,
  });
}

// Simple in-memory brute-force throttle on login (per client IP).
const LOGIN_MAX = 10;
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const loginAttempts = new Map(); // ip -> { count, resetAt }

function loginRateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  let e = loginAttempts.get(ip);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    loginAttempts.set(ip, e);
  }
  if (e.count >= LOGIN_MAX) {
    const retry = Math.ceil((e.resetAt - now) / 1000);
    res.setHeader('Retry-After', String(retry));
    return res.status(429).json({ error: `Trop de tentatives. Réessayez dans ${retry}s.` });
  }
  e.count += 1;
  next();
}

// POST /api/auth/login
router.post('/login', loginRateLimit, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  const user = await User.findOne({ where: { email: String(email).toLowerCase().trim() } });
  if (!user || !(await user.verifyPassword(password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  loginAttempts.delete(req.ip); // reset the counter on success
  setAuthCookie(res, signToken(user));
  res.json({ user });
});

// POST /api/auth/logout
router.post('/logout', (_req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// GET /api/auth/me
router.get('/me', requireAuth, async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user) return res.status(401).json({ error: 'User no longer exists' });
  res.json({ user });
});

// PATCH /api/auth/me  — self-service profile (color and/or avatar)
router.patch('/me', requireAuth, async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user) return res.status(401).json({ error: 'User no longer exists' });

  const { color, avatar } = req.body || {};

  if (color !== undefined) {
    if (color === null || color === '') {
      user.color = null;
    } else if (/^#[0-9a-fA-F]{6}$/.test(color)) {
      user.color = String(color).toLowerCase();
    } else {
      return res.status(400).json({ error: 'Couleur invalide (format #RRGGBB attendu)' });
    }
  }

  if (avatar !== undefined) {
    if (avatar === null) {
      user.avatarData = null;
      user.avatarType = null;
    } else {
      const parsed = parseDataUrlImage(avatar);
      if (!parsed) {
        return res.status(400).json({ error: 'Image invalide : seuls les fichiers JPEG et PNG sont acceptés' });
      }
      if (parsed.data.length > MAX_AVATAR_BYTES) {
        return res.status(413).json({ error: 'Image trop volumineuse (max 2 Mo)' });
      }
      user.avatarData = parsed.data;
      user.avatarType = parsed.contentType;
    }
  }

  await user.save();
  res.json({ user });
});

// GET /api/auth/reset/:token  — check a reset link's validity (public)
router.get('/reset/:token', async (req, res) => {
  const user = await findByValidResetToken(req.params.token);
  if (!user) return res.status(400).json({ error: 'Lien invalide ou expiré' });
  res.json({ valid: true, email: user.email });
});

// POST /api/auth/reset  — set a new password from a reset link (public)
router.post('/reset', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) {
    return res.status(400).json({ error: 'Token et mot de passe requis' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 8 caractères' });
  }
  const user = await findByValidResetToken(token);
  if (!user) return res.status(400).json({ error: 'Lien invalide ou expiré' });

  user.passwordHash = await User.hashPassword(password);
  user.resetTokenHash = null;
  user.resetTokenExpires = null;
  await user.save();
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/* SSO — generic OAuth2 / OIDC authorization-code flow (public)        */
/* ------------------------------------------------------------------ */

// The redirect URI the provider must be configured to call back. Honors the
// reverse-proxy headers (app.set('trust proxy', 1)) so https is detected.
const ssoRedirectUri = (req) => `${req.protocol}://${req.get('host')}/api/auth/sso/callback`;

// Send the user back to the login screen with a readable error.
const ssoFail = (res, msg) => res.redirect('/?sso_error=' + encodeURIComponent(msg));

// GET /api/auth/sso/status  — what the login page needs to render the button.
// Never exposes the client id/secret or endpoints.
router.get('/sso/status', async (_req, res) => {
  const cfg = await getSsoConfig();
  res.json({ enabled: cfg.isUsable(), provider: cfg.provider, label: cfg.label });
});

// GET /api/auth/sso/login  — start the flow: redirect to the provider.
router.get('/sso/login', async (req, res) => {
  const cfg = await getSsoConfig();
  if (!cfg.isUsable()) return ssoFail(res, 'SSO non configuré');

  // State doubles as a CSRF token: a short-lived signed JWT, mirrored in an
  // httpOnly cookie and checked on callback.
  const state = jwt.sign({ n: crypto.randomBytes(16).toString('hex') }, process.env.JWT_SECRET, { expiresIn: '10m' });
  res.cookie('sso_state', state, { httpOnly: true, sameSite: 'lax', secure: cookieSecure(), maxAge: 10 * 60 * 1000 });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: cfg.clientId,
    redirect_uri: ssoRedirectUri(req),
    scope: cfg.scopes || 'openid email profile',
    state,
  });
  res.redirect(`${cfg.authorizationUrl}?${params.toString()}`);
});

// GET /api/auth/sso/callback  — provider redirects here with ?code&state.
router.get('/sso/callback', async (req, res) => {
  const cfg = await getSsoConfig();
  try {
    if (!cfg.isUsable()) return ssoFail(res, 'SSO non configuré');

    const { code, state } = req.query;
    const cookieState = req.cookies && req.cookies.sso_state;
    res.clearCookie('sso_state');
    if (!code || !state || !cookieState || state !== cookieState) return ssoFail(res, 'État SSO invalide');
    try { jwt.verify(String(state), process.env.JWT_SECRET); } catch (_) { return ssoFail(res, 'État SSO expiré'); }

    // 1) Exchange the authorization code for an access token.
    const tokenRes = await fetch(cfg.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: ssoRedirectUri(req),
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret || '',
      }),
    });
    if (!tokenRes.ok) return ssoFail(res, "Échec de l'échange du code SSO");
    const accessToken = (await tokenRes.json()).access_token;
    if (!accessToken) return ssoFail(res, "Aucun jeton d'accès reçu");

    // 2) Fetch the user profile.
    const headers = { Authorization: `Bearer ${accessToken}`, Accept: 'application/json', 'User-Agent': 'recon-sso' };
    const uiRes = await fetch(cfg.userinfoUrl, { headers });
    if (!uiRes.ok) return ssoFail(res, 'Échec de récupération du profil SSO');
    const profile = await uiRes.json();

    let email = profile[cfg.emailField || 'email'];
    // GitHub does not return a private email on /user — fetch the primary one.
    if (!email && cfg.provider === 'github') {
      const emRes = await fetch('https://api.github.com/user/emails', { headers });
      if (emRes.ok) {
        const list = await emRes.json();
        const pick = Array.isArray(list) && (list.find((e) => e.primary && e.verified) || list.find((e) => e.verified));
        email = pick && pick.email;
      }
    }
    if (!email) return ssoFail(res, 'Aucune adresse e-mail fournie par le fournisseur SSO');
    email = String(email).toLowerCase().trim();

    // 3) Resolve (or provision) the local account.
    let user = await User.findOne({ where: { email } });
    if (!user) {
      if (!cfg.autoCreateUsers) {
        return ssoFail(res, "Compte introuvable. Demandez à un administrateur de créer votre compte.");
      }
      const randomPw = crypto.randomBytes(24).toString('hex');
      user = await User.create({
        email,
        passwordHash: await User.hashPassword(randomPw),
        role: cfg.defaultRole === 'admin' ? 'admin' : 'auditor',
      });
    }

    setAuthCookie(res, signToken(user));
    return res.redirect('/');
  } catch (err) {
    console.error('[sso] callback error:', err);
    return ssoFail(res, 'Erreur lors de la connexion SSO');
  }
});

module.exports = router;
