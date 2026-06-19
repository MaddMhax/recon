const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Verifies the auth cookie, then confirms the session is still current against
// the database. Attaches { id, email, role } (read fresh from the DB) to req.user.
//
// The DB check does two things a stateless JWT cannot on its own:
//   - honours `tokenVersion`, so a password change/reset revokes older sessions;
//   - reads the role live, so a demotion or deletion takes effect immediately
//     instead of lingering until the token expires.
async function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  try {
    const user = await User.findByPk(payload.id, {
      attributes: ['id', 'email', 'role', 'tokenVersion'],
    });
    // No user (deleted) or a stale token version (password changed since issue).
    if (!user || (user.tokenVersion || 0) !== (payload.tv || 0)) {
      return res.status(401).json({ error: 'Session expirée, veuillez vous reconnecter' });
    }
    req.user = { id: user.id, email: user.email, role: user.role };
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requireAuth };
