// Must be used after requireAuth. Rejects non-admin users.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès réservé aux administrateurs' });
  }
  return next();
}

module.exports = { requireAdmin };
