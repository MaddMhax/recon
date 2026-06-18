const express = require('express');
const crypto = require('crypto');
const VulnItem = require('../models/VulnItem');
const User = require('../models/User');
const { isUuid } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');

const router = express.Router();
router.use(requireAuth, requireAdmin);

// How long a generated password-reset link stays valid.
const RESET_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24h

const CATALOG_ORDER = [['order', 'ASC'], ['code', 'ASC']];

/* ------------------------------------------------------------------ */
/* Vulnerability catalog (référentiel)                                 */
/* ------------------------------------------------------------------ */

// GET /api/admin/vulns
router.get('/vulns', async (_req, res) => {
  const vulns = await VulnItem.findAll({ order: CATALOG_ORDER });
  res.json({ vulns });
});

// POST /api/admin/vulns
router.post('/vulns', async (req, res) => {
  const { code, category, name } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "L'intitulé est requis" });
  }
  const vuln = await VulnItem.create({
    code: (code || '').trim(),
    category: (category || '').trim(),
    name: name.trim(),
    description: req.body.description || '',
    reference: req.body.reference || '',
    command: req.body.command || '',
    notes: req.body.notes || '',
    order: req.body.order || 0,
  });
  res.status(201).json({ vuln });
});

// POST /api/admin/vulns/reorder  — set the catalog display order.
// Body: { ids: [id, id, ...] } in the desired order. Each item's `order` is set
// to its index, which drives the order in new projects' checklists too.
router.post('/vulns/reorder', async (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids : null;
  if (!ids) return res.status(400).json({ error: "Liste d'identifiants attendue" });
  let pos = 0;
  for (const id of ids) {
    if (!isUuid(id)) continue;
    await VulnItem.update({ order: pos }, { where: { id } });
    pos += 1;
  }
  res.json({ ok: true });
});

// PATCH /api/admin/vulns/:id
router.patch('/vulns/:id', async (req, res) => {
  const vuln = isUuid(req.params.id) ? await VulnItem.findByPk(req.params.id) : null;
  if (!vuln) return res.status(404).json({ error: 'Vulnérabilité introuvable' });
  const allowed = ['code', 'category', 'name', 'description', 'reference', 'command', 'notes', 'order'];
  const update = {};
  for (const k of allowed) if (req.body[k] !== undefined) update[k] = req.body[k];
  await vuln.update(update);
  res.json({ vuln });
});

// DELETE /api/admin/vulns  — wipe the entire catalog (UI requires the admin to
// type "supprimer" to confirm; export reminder shown beforehand).
router.delete('/vulns', async (_req, res) => {
  const deleted = await VulnItem.destroy({ where: {} });
  res.json({ deleted });
});

// DELETE /api/admin/vulns/:id
router.delete('/vulns/:id', async (req, res) => {
  const vuln = isUuid(req.params.id) ? await VulnItem.findByPk(req.params.id) : null;
  if (!vuln) return res.status(404).json({ error: 'Vulnérabilité introuvable' });
  await vuln.destroy();
  res.json({ ok: true });
});

// GET /api/admin/vulns/export  — download the whole catalog as JSON
router.get('/vulns/export', async (_req, res) => {
  const rows = await VulnItem.findAll({ order: CATALOG_ORDER });
  const vulns = rows.map((v) => ({
    code: v.code,
    category: v.category,
    name: v.name,
    description: v.description,
    reference: v.reference,
    command: v.command,
    notes: v.notes,
    order: v.order,
  }));
  res.setHeader('Content-Disposition', 'attachment; filename="recon-referentiel.json"');
  res.json({ vulns });
});

// POST /api/admin/vulns/import  — bulk import from JSON
// Body: { vulns: [...], mode: 'merge' | 'replace' }
router.post('/vulns/import', async (req, res) => {
  const body = req.body || {};
  const list = Array.isArray(body) ? body : body.vulns;
  const mode = body.mode === 'replace' ? 'replace' : 'merge';
  if (!Array.isArray(list)) {
    return res.status(400).json({ error: 'Format invalide : un tableau "vulns" est attendu' });
  }

  if (mode === 'replace') {
    await VulnItem.destroy({ where: {} });
  }

  let created = 0;
  let updated = 0;
  const errors = [];
  // Coerce every field to a string/number — never trust the JSON shape.
  const str = (v) => (v == null ? '' : String(v));
  for (const raw of list) {
    if (!raw || typeof raw !== 'object' || !str(raw.name).trim()) {
      errors.push({ item: raw, error: "L'intitulé (name) est requis" });
      continue;
    }
    const code = str(raw.code).trim();
    const doc = {
      category: str(raw.category),
      name: str(raw.name),
      description: str(raw.description),
      reference: str(raw.reference),
      command: str(raw.command),
      notes: str(raw.notes),
      order: Number(raw.order) || 0,
    };
    if (code) {
      // Merge by code when one is provided.
      const existing = await VulnItem.findOne({ where: { code } });
      if (existing) {
        await existing.update(doc);
        updated += 1;
      } else {
        await VulnItem.create({ ...doc, code });
        created += 1;
      }
    } else {
      // No code: always insert a new entry.
      await VulnItem.create({ ...doc, code: '' });
      created += 1;
    }
  }
  res.json({ mode, created, updated, errors });
});

/* ------------------------------------------------------------------ */
/* User management                                                     */
/* ------------------------------------------------------------------ */

// GET /api/admin/users
router.get('/users', async (_req, res) => {
  const users = await User.findAll({ order: [['createdAt', 'ASC']] });
  res.json({ users });
});

// POST /api/admin/users
router.post('/users', async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe sont requis' });
  }
  const exists = await User.findOne({ where: { email: String(email).toLowerCase().trim() } });
  if (exists) return res.status(409).json({ error: 'Cet utilisateur existe déjà' });

  const user = await User.create({
    email: String(email).toLowerCase().trim(),
    passwordHash: await User.hashPassword(password),
    role: role === 'admin' ? 'admin' : 'auditor',
  });
  res.status(201).json({ user });
});

// PATCH /api/admin/users/:id  — change role and/or reset password
router.patch('/users/:id', async (req, res) => {
  const user = isUuid(req.params.id) ? await User.findByPk(req.params.id) : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const update = {};
  if (req.body.role) {
    const role = req.body.role === 'admin' ? 'admin' : 'auditor';
    // Guardrail: an admin cannot remove their own admin role (avoids lockout).
    if (req.params.id === req.user.id && role !== 'admin') {
      return res.status(400).json({ error: 'Vous ne pouvez pas retirer votre propre rôle administrateur' });
    }
    update.role = role;
  }
  if (req.body.password) update.passwordHash = await User.hashPassword(req.body.password);
  await user.update(update);
  res.json({ user });
});

// POST /api/admin/users/:id/reset-link  — issue a secure password-reset link
// to hand to the user. Only the token hash is stored; the raw token is in the
// returned URL and shown to the admin once.
router.post('/users/:id/reset-link', async (req, res) => {
  const user = isUuid(req.params.id) ? await User.findByPk(req.params.id) : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const token = crypto.randomBytes(32).toString('hex');
  user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
  user.resetTokenExpires = new Date(Date.now() + RESET_TOKEN_TTL_MS);
  await user.save();

  const base = `${req.protocol}://${req.get('host')}`;
  const url = `${base}/reset?token=${token}`;
  res.json({ url, email: user.email, expiresAt: user.resetTokenExpires });
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  }
  const user = isUuid(req.params.id) ? await User.findByPk(req.params.id) : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  await user.destroy();
  res.json({ ok: true });
});

module.exports = router;
