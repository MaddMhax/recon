const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/db');

// Append-only security journal: who did what, to what, from where. Rows are
// never updated or deleted by the app (a database trigger also refuses it,
// see config/db.js). The actor's e-mail and the target's label are copied in,
// so entries stay readable after the user or project is deleted.
class AuditLog extends Model {
  toJSON() {
    const v = this.get({ plain: true });
    return {
      _id: v.id,
      at: v.createdAt,
      actorId: v.actorId,
      actorEmail: v.actorEmail,
      action: v.action,
      targetType: v.targetType,
      targetId: v.targetId,
      targetLabel: v.targetLabel,
      details: v.details || {},
      ip: v.ip,
    };
  }
}

AuditLog.init(
  {
    id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
    actorId: { type: DataTypes.UUID, allowNull: true },
    actorEmail: { type: DataTypes.STRING, allowNull: true },
    // Dotted event name, e.g. "auth.login.failure", "project.member.add".
    action: { type: DataTypes.STRING(64), allowNull: false },
    targetType: { type: DataTypes.STRING(32), allowNull: true },
    targetId: { type: DataTypes.STRING(64), allowNull: true },
    targetLabel: { type: DataTypes.STRING, allowNull: true },
    // Context only — never secrets, passwords or project content.
    details: { type: DataTypes.JSONB, allowNull: false, defaultValue: {} },
    ip: { type: DataTypes.STRING(64), allowNull: true },
  },
  {
    sequelize,
    modelName: 'AuditLog',
    tableName: 'audit_log',
    updatedAt: false,
    indexes: [{ fields: ['createdAt'] }, { fields: ['action'] }, { fields: ['actorId'] }],
  }
);

module.exports = AuditLog;
