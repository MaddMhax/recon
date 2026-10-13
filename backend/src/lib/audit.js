const AuditLog = require('../models/AuditLog');

// Record a security event. Never throws and never blocks the response on
// failure: losing an audit row must not break the action itself, but it is
// reported in the server log.
//
//   audit(req, 'project.delete', { target: ['project', p.id, p.name], details })
//
// The actor defaults to the session user (req.user); pass `actor` ({ id,
// email }) when there is none yet (login, SSO, password reset).
async function audit(req, action, { actor, target, details } = {}) {
  const who = actor || (req && req.user) || null;
  const [targetType, targetId, targetLabel] = target || [];
  try {
    await AuditLog.create({
      actorId: (who && who.id) || null,
      actorEmail: (who && who.email) || null,
      action,
      targetType: targetType || null,
      targetId: targetId == null ? null : String(targetId).slice(0, 64),
      targetLabel: targetLabel == null ? null : String(targetLabel).slice(0, 255),
      details: details || {},
      ip: req ? String(req.ip || '').slice(0, 64) || null : null,
    });
  } catch (err) {
    console.error('[audit] failed to record', action, err.message);
  }
}

module.exports = { audit };
