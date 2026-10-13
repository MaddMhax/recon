const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { getSsoConfig } = require('../models/SsoConfig');
const { requireAuth, resolveSession } = require('../middleware/auth');
const { sanitizeImage } = require('../lib/image');
const { disconnectUser } = require('../realtime');

const router = express.Router();

const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');

const MAX_AVATAR_BYTES = 2 * 1024 * 1024; // 2 MB

// Parse a data URL into a validated, sanitized PNG/JPEG. Returns null unless
// the bytes are a well-formed image of the declared type: the full file
// structure is checked (not just the magic bytes), and the stored copy is
// rebuilt without metadata or trailing data (see lib/image.js).
function parseDataUrlImage(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  // Cheap size bound before decoding (base64 inflates by 4/3).
  if (dataUrl.length > Math.ceil(MAX_AVATAR_BYTES * 4 / 3) + 64) return { tooLarge: true };
  const m = dataUrl.match(/^data:(image\/png|image\/jpeg);base64,([A-Za-z0-9+/]+={0,2})$/);
  if (!m) return null;
  const data = Buffer.from(m[2], 'base64');
  if (data.length > MAX_AVATAR_BYTES) return { tooLarge: true };
  return sanitizeImage(data, m[1]);
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
    { id: user.id, email: user.email, role: user.role, tv: user.tokenVersion || 0 },
    process.env.JWT_SECRET,
    { algorithm: 'HS256', expiresIn: process.env.JWT_EXPIRES_IN || '12h' }
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
const pwAttempts = new Map(); // user id -> { count, resetAt } (change-password)

// Drop expired throttle entries so the maps cannot grow without bound.
setInterval(() => {
  const now = Date.now();
  for (const m of [loginAttempts, pwAttempts]) {
    for (const [k, e] of m) if (now > e.resetAt) m.delete(k);
  }
}, LOGIN_WINDOW_MS).unref();

// Compared against when the email is unknown, so a login attempt costs one
// bcrypt check either way and response time does not reveal which emails exist.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10);

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
  const ok = user ? await user.verifyPassword(String(password)) : await bcrypt.compare(String(password), DUMMY_HASH);
  if (!user || !ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  loginAttempts.delete(req.ip); // reset the counter on success
  setAuthCookie(res, signToken(user));
  res.json({ user });
});

// POST /api/auth/logout
// Revokes the session server-side (bumps tokenVersion) so a copied or stolen
// cookie stops working too — not just the browser's copy. Note: this signs the
// account out on every device, since sessions are not tracked individually.
router.post('/logout', async (req, res) => {
  const session = await resolveSession(req.cookies && req.cookies.token);
  if (session) {
    await User.increment('tokenVersion', { where: { id: session.id } });
    disconnectUser(req.app, session.id);
  }
  res.clearCookie('token', { httpOnly: true, sameSite: 'lax', secure: cookieSecure() });
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
      if (parsed && parsed.tooLarge) {
        return res.status(413).json({ error: 'Image trop volumineuse (max 2 Mo)' });
      }
      if (!parsed) {
        return res.status(400).json({ error: 'Image invalide : le fichier doit être une image JPEG ou PNG valide' });
      }
      user.avatarData = parsed.data;
      user.avatarType = parsed.contentType;
    }
  }

  await user.save();
  res.json({ user });
});

// Throttle current-password guessing on the change-password endpoint, keyed by
// the authenticated user (falls back to IP). Separate from the login limiter so
// the two don't share a budget.
function passwordChangeRateLimit(req, res, next) {
  const key = (req.user && req.user.id) || req.ip || 'unknown';
  const now = Date.now();
  let e = pwAttempts.get(key);
  if (!e || now > e.resetAt) {
    e = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    pwAttempts.set(key, e);
  }
  if (e.count >= LOGIN_MAX) {
    const retry = Math.ceil((e.resetAt - now) / 1000);
    res.setHeader('Retry-After', String(retry));
    return res.status(429).json({ error: `Trop de tentatives. Réessayez dans ${retry}s.` });
  }
  e.count += 1;
  next();
}

// POST /api/auth/me/password  — change own password (requires the current one)
router.post('/me/password', requireAuth, passwordChangeRateLimit, async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user) return res.status(401).json({ error: 'User no longer exists' });

  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Mot de passe actuel et nouveau mot de passe requis' });
  }
  if (!(await user.verifyPassword(String(currentPassword)))) {
    return res.status(400).json({ error: 'Mot de passe actuel incorrect' });
  }
  if (String(newPassword).length < 8) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit faire au moins 8 caractères' });
  }

  user.passwordHash = await User.hashPassword(newPassword);
  // Revoke every other session and any outstanding reset link, then re-issue a
  // fresh cookie so the user who just changed their password stays signed in.
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  user.resetTokenHash = null;
  user.resetTokenExpires = null;
  await user.save();
  pwAttempts.delete(req.user.id); // reset the counter on success
  disconnectUser(req.app, user.id); // this tab reconnects with the new cookie
  setAuthCookie(res, signToken(user));
  res.json({ ok: true });
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
  // Invalidate any session opened before the reset (the whole point of a reset).
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  user.resetTokenHash = null;
  user.resetTokenExpires = null;
  await user.save();
  disconnectUser(req.app, user.id);
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/* SSO — generic OAuth2 / OIDC authorization-code flow (public)        */
/* ------------------------------------------------------------------ */

// The redirect URI the provider must be configured to call back. Honors the
// reverse-proxy headers (app.set('trust proxy', 1)) so https is detected.
const ssoRedirectUri = (req) => `${req.protocol}://${req.get('host')}/api/auth/sso/callback`;

// Send the user back to the login screen with a readable error.
const ssoFail = (res, msg) => res.redirect('/login?sso_error=' + encodeURIComponent(msg));

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
    try { jwt.verify(String(state), process.env.JWT_SECRET, { algorithms: ['HS256'] }); } catch (_) { return ssoFail(res, 'État SSO expiré'); }

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
    if (!email || typeof email !== 'string') return ssoFail(res, 'Aucune adresse e-mail fournie par le fournisseur SSO');
    // Accounts are matched by email, so an address the provider has not verified
    // could be used to take over an existing local account (e.g. an admin).
    if (profile.email_verified === false || profile.email_verified === 'false') {
      return ssoFail(res, "L'adresse e-mail n'est pas vérifiée auprès du fournisseur SSO");
    }
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
        ssoProvider: cfg.provider, // marks the account as SSO-provisioned
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
