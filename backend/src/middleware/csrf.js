const crypto = require('crypto');

// Mirror the auth cookie's Secure logic so the CSRF cookie behaves identically
// across HTTP (localhost) and HTTPS deployments. See routes/auth.js for why.
function cookieSecure() {
  if (process.env.COOKIE_SECURE !== undefined) {
    return /^(1|true|yes)$/i.test(process.env.COOKIE_SECURE);
  }
  return process.env.NODE_ENV === 'production';
}

const CSRF_COOKIE = 'csrf';
const CSRF_HEADER = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Double-submit cookie pattern. We hand the client a random token in a
// JS-readable cookie; the SPA echoes it back in the X-CSRF-Token header on every
// state-changing request. A cross-site attacker can ride the auth cookie but
// cannot read this token (same-origin policy) nor set a custom header on a
// simple form post, so the forged request fails the comparison below.
function issueCsrfToken(req, res, next) {
  let token = req.cookies && req.cookies[CSRF_COOKIE];
  if (!token || !/^[0-9a-f]{64}$/.test(token)) {
    token = crypto.randomBytes(32).toString('hex');
    res.cookie(CSRF_COOKIE, token, {
      httpOnly: false, // must be readable by JS to echo into the header
      sameSite: 'lax',
      secure: cookieSecure(),
      path: '/',
    });
  }
  req.csrfToken = token;
  next();
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Reject mutating requests whose header token does not match the cookie token.
// Safe (read-only) methods pass through untouched. SameSite=Lax already blocks
// most cross-site sends; this is the belt-and-suspenders layer.
function requireCsrf(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const cookie = req.cookies && req.cookies[CSRF_COOKIE];
  const header = req.get(CSRF_HEADER);
  if (!cookie || !header || !safeEqual(cookie, header)) {
    return res.status(403).json({ error: 'Jeton CSRF manquant ou invalide' });
  }
  next();
}

module.exports = { issueCsrfToken, requireCsrf, CSRF_COOKIE, CSRF_HEADER };
