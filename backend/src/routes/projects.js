const express = require('express');
const crypto = require('crypto');
const Project = require('../models/Project');
const VulnItem = require('../models/VulnItem');
const Referential = require('../models/Referential');
const User = require('../models/User');
const ProjectMember = require('../models/ProjectMember');
const { getDefaultReferential } = require('../models/Referential');
const { isUuid, sequelize } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { broadcast, evictFromProject, closeProjectRoom } = require('../realtime');
const {
  accessLevel, canManage, visibleProjectsWhere, loadProject, requireManage,
} = require('../lib/projectAccess');
const { audit } = require('../lib/audit');

const router = express.Router();
router.use(requireAuth);

const PROJECT_STATUSES = ['planning', 'active', 'reporting', 'completed', 'archived'];
// Free-text fields are stored and re-rendered for every collaborator: accept
// strings only (never objects/arrays smuggled into the JSONB checklist).
const str = (v) => (v == null ? '' : String(v));

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

// Generate a share token that is not already taken (collisions are astronomically
// unlikely at 64 bits, but the retry keeps the unique constraint from ever firing).
async function uniqueShareSlug() {
  for (let i = 0; i < 5; i++) {
    const slug = Project.genShareSlug();
    if (!(await Project.findOne({ where: { shareSlug: slug } }))) return slug;
  }
  return Project.genShareSlug();
}

// Public shape of a user shown in a project's collaborator list.
const memberView = (u) => ({
  _id: u.id,
  email: u.email,
  color: u.color || null,
  hasAvatar: !!u.avatarType,
  updatedAt: u.updatedAt,
});
const MEMBER_ATTRS = ['id', 'email', 'color', 'avatarType', 'updatedAt'];

// Owner + invited collaborators of a project.
async function projectMembers(project) {
  const rows = await ProjectMember.findAll({ where: { projectId: project.id }, order: [['createdAt', 'ASC']] });
  const ids = [project.ownerId, ...rows.map((r) => r.userId)];
  const users = await User.findAll({ where: { id: ids }, attributes: MEMBER_ATTRS });
  const byId = new Map(users.map((u) => [u.id, u]));
  const owner = byId.get(project.ownerId);
  return {
    owner: owner ? memberView(owner) : null, // null when the owner account was deleted
    members: rows.map((r) => byId.get(r.userId)).filter(Boolean).map(memberView),
  };
}

// Full detail payload (detail route, share link, after a membership change).
async function detailPayload(project, access) {
  const names = await referentialNameMap();
  return {
    project,
    referentialName: names[project.referentialId] || null,
    access,
    ...(await projectMembers(project)),
  };
}

// Resolve invitees given as user ids or e-mail addresses. Returns
// { users } or { unknown: [identifier, ...] }.
async function resolveInvitees(list) {
  const users = [];
  const unknown = [];
  for (const raw of list) {
    const ident = String(raw == null ? '' : raw).trim();
    if (!ident) continue;
    const user = isUuid(ident)
      ? await User.findByPk(ident, { attributes: MEMBER_ATTRS })
      : await User.findOne({ where: { email: ident.toLowerCase() }, attributes: MEMBER_ATTRS });
    if (user) users.push(user);
    else unknown.push(ident);
  }
  return unknown.length ? { unknown } : { users };
}

// Add collaborators (skipping the owner and existing members).
async function addMembers(project, users, invitedById) {
  for (const u of users) {
    if (u.id === project.ownerId) continue;
    await ProjectMember.findOrCreate({
      where: { projectId: project.id, userId: u.id },
      defaults: { invitedById },
    });
  }
}

// Push the new collaborator list to everyone on the project.
async function broadcastMembers(req, project) {
  broadcast(req.app, project.id, 'members:update', await projectMembers(project), req.get('x-socket-id'));
}

// GET /api/projects  — list (lightweight, with progress), limited to the
// projects the caller owns or was invited to (admins see all).
router.get('/', async (req, res) => {
  const projects = await Project.findAll({
    where: await visibleProjectsWhere(req.user),
    order: [['updatedAt', 'DESC']],
  });
  const names = await referentialNameMap();
  const summary = projects.map((p) => {
    const checklist = p.checklist || [];
    const total = checklist.length;
    const done = checklist.filter((c) => c.verified).length;
    const findings = checklist.filter((c) => c.verified && c.vulnerable).length;
    return {
      _id: p.id,
      name: p.name,
      shareSlug: p.shareSlug,
      status: p.status,
      referential: names[p.referentialId] || null,
      // Lets the list tell "my projects" from "shared with me".
      access: p.ownerId === req.user.id ? 'owner' : (req.user.role === 'admin' ? 'admin' : 'member'),
      updatedAt: p.updatedAt,
      progress: { total, done, findings },
    };
  });
  res.json({ projects: summary });
});

// POST /api/projects
router.post('/', async (req, res) => {
  const { name, scope, notes, status } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Le nom du projet est requis' });
  }
  // Resolve the chosen referential, falling back to the default one.
  let referentialId = req.body && req.body.referentialId;
  if (!referentialId || !isUuid(referentialId) || !(await Referential.findByPk(referentialId))) {
    const def = await getDefaultReferential();
    referentialId = def ? def.id : null;
  }
  // Collaborators invited at creation (ids or e-mails). Resolved before the
  // project exists so a typo does not leave a half-shared project behind.
  let invitees = [];
  if (req.body.members !== undefined) {
    if (!Array.isArray(req.body.members)) return res.status(400).json({ error: 'Liste de collaborateurs invalide' });
    const r = await resolveInvitees(req.body.members);
    if (r.unknown) return res.status(400).json({ error: `Utilisateur introuvable : ${r.unknown.join(', ')}` });
    invitees = r.users;
  }
  const checklist = referentialId ? await buildChecklistFromCatalog(referentialId) : [];
  const project = await Project.create({
    name: name.trim(),
    scope: str(scope),
    notes: str(notes),
    status: PROJECT_STATUSES.includes(status) ? status : 'active',
    ownerId: req.user.id,
    referentialId,
    shareSlug: await uniqueShareSlug(),
    checklist,
  });
  await addMembers(project, invitees, req.user.id);
  await audit(req, 'project.create', {
    target: ['project', project.id, project.name],
    details: { members: invitees.filter((u) => u.id !== req.user.id).map((u) => u.email) },
  });
  res.status(201).json({ project });
});

// GET /api/projects/by-slug/:slug  — resolve a share link to its project. Same
// payload as the detail route so the frontend can open it in one round-trip.
// Declared before "/:id" so the two-segment path is matched here, not there.
// The link is only a convenience: it opens the project for its owner and
// collaborators, and is a plain 404 for everyone else.
router.get('/by-slug/:slug', async (req, res) => {
  const project = await Project.findOne({ where: { shareSlug: String(req.params.slug) } });
  const access = await accessLevel(req.user, project);
  if (!access) {
    if (project) await audit(req, 'project.access_denied', { target: ['project', project.id, project.name], details: { via: 'share_link' } });
    return res.status(404).json({ error: 'Projet introuvable' });
  }
  res.json(await detailPayload(project, access));
});

// Every /:id route below requires access to the project (else 404).
router.use('/:id', loadProject);

// GET /api/projects/:id  — full detail
router.get('/:id', async (req, res) => {
  res.json(await detailPayload(req.project, req.access));
});

// PATCH /api/projects/:id  — update project metadata
router.patch('/:id', async (req, res) => {
  const { project } = req;

  const allowed = ['name', 'scope', 'notes', 'status', 'variables'];
  const update = {};
  for (const k of allowed) {
    if (req.body[k] === undefined) continue;
    if (k === 'variables') {
      update.variables = Array.isArray(req.body.variables)
        ? req.body.variables.map((v) => ({ name: String((v && v.name) || ''), value: String((v && v.value) || '') }))
        : [];
    } else if (k === 'status') {
      if (!PROJECT_STATUSES.includes(req.body.status)) return res.status(400).json({ error: 'Statut invalide' });
      update.status = req.body.status;
    } else if (k === 'name') {
      const name = str(req.body.name).trim();
      if (!name) return res.status(400).json({ error: 'Le nom du projet est requis' });
      update.name = name;
    } else {
      update[k] = str(req.body[k]);
    }
  }
  await project.update(update);
  // Field names only: project content (scope, notes...) stays out of the log.
  await audit(req, 'project.update', { target: ['project', project.id, project.name], details: { fields: Object.keys(update) } });
  broadcast(req.app, project.id, 'project:update', { fields: update }, req.get('x-socket-id'));
  res.json({ project });
});

// DELETE /api/projects/:id  — owner (or admin) only
router.delete('/:id', requireManage, async (req, res) => {
  const { project } = req;
  await ProjectMember.destroy({ where: { projectId: project.id } });
  await project.destroy();
  await audit(req, 'project.delete', { target: ['project', project.id, project.name] });
  broadcast(req.app, project.id, 'project:deleted', {}, req.get('x-socket-id'));
  closeProjectRoom(req.app, project.id);
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/* Collaborators                                                       */
/* ------------------------------------------------------------------ */

// GET /api/projects/:id/members
router.get('/:id/members', async (req, res) => {
  res.json({ access: req.access, ...(await projectMembers(req.project)) });
});

// POST /api/projects/:id/members  { user: "<id or e-mail>" }  — owner/admin only
router.post('/:id/members', requireManage, async (req, res) => {
  const ident = req.body && (req.body.user ?? req.body.userId ?? req.body.email);
  const r = await resolveInvitees([ident]);
  if (r.unknown || !r.users.length) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const [user] = r.users;
  if (user.id === req.project.ownerId) return res.status(400).json({ error: 'Le propriétaire a déjà accès au projet' });
  await addMembers(req.project, [user], req.user.id);
  await audit(req, 'project.member.add', { target: ['project', req.project.id, req.project.name], details: { member: user.email } });
  await broadcastMembers(req, req.project);
  res.status(201).json(await projectMembers(req.project));
});

// DELETE /api/projects/:id/members/:userId  — the owner/admin removes a
// collaborator, or a collaborator leaves the project.
router.delete('/:id/members/:userId', async (req, res) => {
  const { userId } = req.params;
  const self = userId === req.user.id;
  if (!self && !canManage(req.access)) {
    return res.status(403).json({ error: 'Action réservée au propriétaire du projet' });
  }
  const removed = isUuid(userId)
    ? await ProjectMember.destroy({ where: { projectId: req.project.id, userId } })
    : 0;
  if (!removed) return res.status(404).json({ error: "Ce collaborateur n'est pas membre du projet" });
  // Cut the live feed immediately: their open sockets leave the project room.
  evictFromProject(req.app, req.project.id, userId);
  const gone = self ? null : await User.findByPk(userId, { attributes: ['email'] });
  await audit(req, self ? 'project.member.leave' : 'project.member.remove', {
    target: ['project', req.project.id, req.project.name],
    details: self ? {} : { member: gone ? gone.email : userId },
  });
  await broadcastMembers(req, req.project);
  res.json(await projectMembers(req.project));
});

// The checklist is one JSONB array, so every change is a read-modify-write of
// the whole array. Run it on a freshly read, row-locked copy inside a
// transaction: concurrent writers (several auditors on one project) then queue
// up instead of overwriting each other's changes. `fn(project)` mutates and
// returns a result; the project is saved before the lock is released. Resolves
// to null if the project vanished in the meantime.
function withLockedProject(id, fn) {
  return sequelize.transaction(async (transaction) => {
    const project = await Project.findByPk(id, { transaction, lock: transaction.LOCK.UPDATE });
    if (!project) return null;
    const result = await fn(project);
    await project.save({ transaction });
    return { project, result };
  });
}

// PATCH /api/projects/:id/checklist/:itemId  — update a single check
router.patch('/:id/checklist/:itemId', async (req, res) => {
  const out = await withLockedProject(req.project.id, (project) => {
    // Work on a copy of the JSONB array and reassign it so Sequelize detects
    // the change (in-place mutation of a JSONB value is not tracked).
    const checklist = (project.checklist || []).map((c) => ({ ...c }));
    const item = checklist.find((c) => c._id === req.params.itemId);
    if (!item) return null;

    const allowed = ['verified', 'vulnerable', 'command', 'notes'];
    for (const k of allowed) {
      if (req.body[k] === undefined) continue;
      if (k === 'verified') item.verified = !!req.body[k];
      else if (k === 'vulnerable') item.vulnerable = req.body[k] === null ? null : !!req.body[k];
      else item[k] = str(req.body[k]);
    }
    // While unverified, the vulnerability decision is reset to "not decided".
    if (item.verified === false) item.vulnerable = null;

    project.checklist = checklist;
    return item;
  });
  if (!out) return res.status(404).json({ error: 'Projet introuvable' });
  if (!out.result) return res.status(404).json({ error: 'Élément introuvable' });
  const item = out.result;
  broadcast(req.app, req.project.id, 'item:update', { item }, req.get('x-socket-id'));
  res.json({ item });
});

// POST /api/projects/:id/resync  — pull any new catalog items into this project
router.post('/:id/resync', async (req, res) => {
  // Dedupe by code when present, otherwise fall back to the name (codes are
  // optional, so empty codes must not collapse into a single entry).
  const key = (c) => (c.code ? `code:${c.code}` : `name:${c.name}`);
  // Resync from the project's own referential (fall back to the default one for
  // projects created before referentials existed).
  let referentialId = req.project.referentialId;
  if (!referentialId) {
    const def = await getDefaultReferential();
    referentialId = def ? def.id : null;
  }
  const catalog = referentialId ? await buildChecklistFromCatalog(referentialId) : [];

  const out = await withLockedProject(req.project.id, (project) => {
    const checklist = project.checklist || [];
    const existing = new Set(checklist.map(key));
    const added = catalog.filter((c) => !existing.has(key(c)));
    if (added.length) project.checklist = checklist.concat(added);
    return added.length;
  });
  if (!out) return res.status(404).json({ error: 'Projet introuvable' });
  if (out.result) await audit(req, 'project.resync', { target: ['project', req.project.id, req.project.name], details: { added: out.result } });
  // Tell collaborators to reload the project (checklist length changed).
  if (out.result) broadcast(req.app, req.project.id, 'project:reload', {}, req.get('x-socket-id'));
  res.json({ added: out.result, project: out.project });
});

module.exports = router;
