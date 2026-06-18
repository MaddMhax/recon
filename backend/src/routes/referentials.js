const express = require('express');
const Referential = require('../models/Referential');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

// GET /api/referentials  — list for any authenticated user (e.g. to pick one
// when creating a project). Management (create/rename/delete) lives under
// /api/admin/referentials.
router.get('/', async (_req, res) => {
  const referentials = await Referential.findAll({ order: [['order', 'ASC'], ['name', 'ASC']] });
  res.json({ referentials });
});

module.exports = router;
