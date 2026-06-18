const jwt = require('jsonwebtoken');

// Verifies the auth cookie and attaches { id, email, role } to req.user.
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

module.exports = { requireAuth };
