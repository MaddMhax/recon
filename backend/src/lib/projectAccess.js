const { Op } = require('sequelize');
const Project = require('../models/Project');
const ProjectMember = require('../models/ProjectMember');
const { isUuid } = require('../config/db');
const { audit } = require('./audit');

// Project access model:
//   - owner   : the creator (Project.ownerId) — full control, invites/removes
//               collaborators, deletes the project;
//   - member  : invited collaborator — reads and edits the checklist, variables
//               and metadata, may leave the project;
//   - admin   : application administrators can open every project (to recover
//               one whose owner left) and manage it like its owner.
// Anyone else gets a 404, so a project's existence is not revealed.

// Access level of `user` on `project`: 'owner' | 'admin' | 'member' | null.
async function accessLevel(user, project) {
  if (!user || !project) return null;
  if (project.ownerId === user.id) return 'owner';
  if (user.role === 'admin') return 'admin';
  const m = await ProjectMember.findOne({ where: { projectId: project.id, userId: user.id } });
  return m ? 'member' : null;
}

const canManage = (level) => level === 'owner' || level === 'admin';

// Same check from a bare project id (used by the realtime layer).
async function accessLevelById(user, projectId) {
  if (!isUuid(projectId)) return null;
  const project = await Project.findByPk(projectId, { attributes: ['id', 'ownerId'] });
  return accessLevel(user, project);
}

// Sequelize `where` restricting a project query to what `user` may see.
async function visibleProjectsWhere(user) {
  if (user.role === 'admin') return {};
  const memberships = await ProjectMember.findAll({ where: { userId: user.id }, attributes: ['projectId'] });
  return {
    [Op.or]: [
      { ownerId: user.id },
      { id: { [Op.in]: memberships.map((m) => m.projectId) } },
    ],
  };
}

// Express middleware for /:id routes: loads the project into req.project and
// the caller's level into req.access, or answers 404.
async function loadProject(req, res, next) {
  const project = isUuid(req.params.id) ? await Project.findByPk(req.params.id) : null;
  const level = await accessLevel(req.user, project);
  if (!level) {
    // An existing project the caller may not see: worth a trace (probing or
    // a stale link). Unknown ids are just 404s.
    if (project) await audit(req, 'project.access_denied', { target: ['project', project.id, project.name], details: { method: req.method } });
    return res.status(404).json({ error: 'Projet introuvable' });
  }
  req.project = project;
  req.access = level;
  return next();
}

// Guard for owner-only actions (must follow loadProject).
function requireManage(req, res, next) {
  if (!canManage(req.access)) {
    return res.status(403).json({ error: 'Action réservée au propriétaire du projet' });
  }
  return next();
}

module.exports = { accessLevel, accessLevelById, canManage, visibleProjectsWhere, loadProject, requireManage };
