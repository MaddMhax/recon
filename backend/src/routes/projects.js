const express = require('express');
const crypto = require('crypto');
const Project = require('../models/Project');
const VulnItem = require('../models/VulnItem');
const Referential = require('../models/Referential');
const { getDefaultReferential } = require('../models/Referential');
const { isUuid } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { broadcast } = require('../realtime');

const router = express.Router();
router.use(requireAuth);

// { referentialId: name } map, for labelling projects in responses.
async function referentialNameMap() {
  const refs = await Referential.findAll();
  return Object.fromEntries(refs.map((r) => [r.id, r.name]));
}

// Build a fresh checklist snapshot from one referential's catalog. Each embedded
// item gets its own stable id (`_id`) so the frontend can address it.
async function buildChecklistFromCatalog(referentialId) {
  const items = await VulnItem.findAll({
    where: { referentialId },
    order: [['order', 'ASC'], ['code', 'ASC']],
  });
  return items.map((v) => ({
    _id: crypto.randomUUID(),
    code: v.code,
    category: v.category,
    name: v.name,
    description: v.description || '',
    reference: v.reference || '',
    command: v.command || '', // default verification command from the catalog
    notes: v.notes || '',
    verified: false,
    vulnerable: null, // not decided yet
  }));
}

// GET /api/projects  — list (lightweight, with progress)
router.get('/', async (_req, res) => {
  const projects = await Project.findAll({ order: [['updatedAt', 'DESC']] });
  const names = await referentialNameMap();
  const summary = projects.map((p) => {
    const checklist = p.checklist || [];
    const total = checklist.length;
    const done = checklist.filter((c) => c.verified).length;
    const findings = checklist.filter((c) => c.verified && c.vulnerable).length;
    return {
      _id: p.id,
      name: p.name,
      status: p.status,
      referential: names[p.referentialId] || null,
      updatedAt: p.updatedAt,
      progress: { total, done, findings },
    };
  });
  res.json({ projects: summary });
});

// POST /api/projects
router.post('/', async (req, res) => {
  const { name, scope, notes, status } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Le nom du projet est requis' });
  }
  // Resolve the chosen referential, falling back to the default one.
  let referentialId = req.body && req.body.referentialId;
  if (!referentialId || !isUuid(referentialId) || !(await Referential.findByPk(referentialId))) {
    const def = await getDefaultReferential();
    referentialId = def ? def.id : null;
  }
  const checklist = referentialId ? await buildChecklistFromCatalog(referentialId) : [];
  const project = await Project.create({
    name: name.trim(),
    scope: scope || '',
    notes: notes || '',
    status: status || 'active',
    ownerId: req.user.id,
    referentialId,
    checklist,
  });
  res.status(201).json({ project });
});

// GET /api/projects/:id  — full detail
router.get('/:id', async (req, res) => {
  const project = isUuid(req.params.id) ? await Project.findByPk(req.params.id) : null;
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });
  const names = await referentialNameMap();
  res.json({ project, referentialName: names[project.referentialId] || null });
});

// PATCH /api/projects/:id  — update project metadata
router.patch('/:id', async (req, res) => {
  const project = isUuid(req.params.id) ? await Project.findByPk(req.params.id) : null;
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });

  const allowed = ['name', 'scope', 'notes', 'status', 'variables'];
  const update = {};
  for (const k of allowed) {
    if (req.body[k] === undefined) continue;
    if (k === 'variables') {
      update.variables = Array.isArray(req.body.variables)
        ? req.body.variables.map((v) => ({ name: String((v && v.name) || ''), value: String((v && v.value) || '') }))
        : [];
    } else {
      update[k] = req.body[k];
    }
  }
  await project.update(update);
  broadcast(req.app, project.id, 'project:update', { fields: update }, req.get('x-socket-id'));
  res.json({ project });
});

// DELETE /api/projects/:id
router.delete('/:id', async (req, res) => {
  const project = isUuid(req.params.id) ? await Project.findByPk(req.params.id) : null;
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });
  await project.destroy();
  broadcast(req.app, project.id, 'project:deleted', {}, req.get('x-socket-id'));
  res.json({ ok: true });
});

// PATCH /api/projects/:id/checklist/:itemId  — update a single check
router.patch('/:id/checklist/:itemId', async (req, res) => {
  const project = isUuid(req.params.id) ? await Project.findByPk(req.params.id) : null;
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });

  // Work on a copy of the JSONB array and reassign it so Sequelize detects the
  // change (in-place mutation of a JSONB value is not tracked).
  const checklist = (project.checklist || []).map((c) => ({ ...c }));
  const item = checklist.find((c) => c._id === req.params.itemId);
  if (!item) return res.status(404).json({ error: 'Élément introuvable' });

  const allowed = ['verified', 'vulnerable', 'command', 'notes'];
  for (const k of allowed) {
    if (req.body[k] === undefined) continue;
    if (k === 'verified') item.verified = !!req.body[k];
    else if (k === 'vulnerable') item.vulnerable = req.body[k] === null ? null : !!req.body[k];
    else item[k] = req.body[k];
  }
  // While unverified, the vulnerability decision is reset to "not decided".
  if (item.verified === false) item.vulnerable = null;

  project.checklist = checklist;
  await project.save();
  broadcast(req.app, project.id, 'item:update', { item }, req.get('x-socket-id'));
  res.json({ item });
});

// POST /api/projects/:id/resync  — pull any new catalog items into this project
router.post('/:id/resync', async (req, res) => {
  const project = isUuid(req.params.id) ? await Project.findByPk(req.params.id) : null;
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });
  // Dedupe by code when present, otherwise fall back to the name (codes are
  // optional, so empty codes must not collapse into a single entry).
  const key = (c) => (c.code ? `code:${c.code}` : `name:${c.name}`);
  const checklist = (project.checklist || []).map((c) => ({ ...c }));
  const existing = new Set(checklist.map(key));
  // Resync from the project's own referential (fall back to the default one for
  // projects created before referentials existed).
  let referentialId = project.referentialId;
  if (!referentialId) {
    const def = await getDefaultReferential();
    referentialId = def ? def.id : null;
  }
  const catalog = referentialId ? await buildChecklistFromCatalog(referentialId) : [];
  const added = catalog.filter((c) => !existing.has(key(c)));

  project.checklist = checklist.concat(added);
  await project.save();
  // Tell collaborators to reload the project (checklist length changed).
  if (added.length) broadcast(req.app, project.id, 'project:reload', {}, req.get('x-socket-id'));
  res.json({ added: added.length, project });
});

module.exports = router;
