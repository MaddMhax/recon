const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Verifies a signed session token, then confirms the session is still current
// against the database. Resolves to { id, email, role } (read fresh from the DB)
// or null when there is no valid session.
//
// The DB check does two things a stateless JWT cannot on its own:
//   - honours `tokenVersion`, so a password change/reset or a logout revokes
//     older sessions;
//   - reads the role live, so a demotion or deletion takes effect immediately
//     instead of lingering until the token expires.
async function resolveSession(token) {
  if (!token || typeof token !== 'string') return null;

  let payload;
  try {
    // Pin the algorithm: only our own HMAC-signed tokens are acceptable.
    payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (_) {
    return null;
  }

  const user = await User.findByPk(payload.id, {
    attributes: ['id', 'email', 'role', 'tokenVersion'],
  });
  // No user (deleted) or a stale token version (password changed since issue).
  if (!user || (user.tokenVersion || 0) !== (payload.tv || 0)) return null;
  return { id: user.id, email: user.email, role: user.role };
}

// API guard: attaches the session user to req.user, or answers 401 (JSON).
async function requireAuth(req, res, next) {
  try {
    const user = await resolveSession(req.cookies && req.cookies.token);
    if (!user) return res.status(401).json({ error: 'Session expirée, veuillez vous reconnecter' });
    req.user = user;
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requireAuth, resolveSession };
