const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/db');

// The checklist and variables are embedded as JSONB — each project owns an
// independent, editable copy of its checklist, exactly as with the previous
// document model. Checklist item shape (each carries its own `_id` for the API):
//   { _id, code, category, name, description, reference,
//     verified: bool, vulnerable: bool|null, command, notes }
// Variable shape: { name, value }
class Project extends Model {
  toJSON() {
    const v = this.get({ plain: true });
    return {
      _id: v.id,
      name: v.name,
      client: v.client,
      scope: v.scope,
      variables: v.variables || [],
      status: v.status,
      notes: v.notes,
      owner: v.ownerId,
      referentialId: v.referentialId,
      checklist: v.checklist || [],
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
    };
  }
}

Project.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    name: { type: DataTypes.STRING, allowNull: false },
    client: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    scope: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    variables: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
    status: {
      type: DataTypes.ENUM('planning', 'active', 'reporting', 'completed', 'archived'),
      allowNull: false,
      defaultValue: 'active',
    },
    notes: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    // Owner user id. Kept as a plain UUID column (no FK constraint) to keep
    // table creation order-independent and deployment simple.
    ownerId: { type: DataTypes.UUID, allowNull: false },
    // Source referential the checklist was snapshotted from (used by resync).
    // Nullable so projects created before referentials existed still load.
    referentialId: { type: DataTypes.UUID, allowNull: true },
    checklist: { type: DataTypes.JSONB, allowNull: false, defaultValue: [] },
  },
  {
    sequelize,
    modelName: 'Project',
    tableName: 'projects',
  }
);

module.exports = Project;
