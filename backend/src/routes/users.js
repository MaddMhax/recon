const express = require('express');
const User = require('../models/User');
const { isUuid } = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

// GET /api/users/:id/avatar  — serve the stored avatar bytes safely.
// The image is returned with a fixed image content-type, nosniff (set globally)
// and a locked-down CSP/sandbox so it can never be interpreted as active
// content even if a polyglot slipped through validation.
router.get('/:id/avatar', async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(400).end();
  const user = await User.findByPk(req.params.id, { attributes: ['avatarData', 'avatarType'] });
  if (!user || !user.avatarData || !user.avatarType) return res.status(404).end();

  res.setHeader('Content-Type', user.avatarType);
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Cache-Control', 'private, max-age=300');
  res.send(user.avatarData);
});

module.exports = router;
