const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/db');

// Collaborators invited onto a project by its owner. The owner itself is not
// stored here (it is Project.ownerId). Plain UUID columns without FK
// constraints, like the other tables; the app cascades deletes itself.
class ProjectMember extends Model {}

ProjectMember.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    projectId: { type: DataTypes.UUID, allowNull: false },
    userId: { type: DataTypes.UUID, allowNull: false },
    // Who sent the invitation (for traceability).
    invitedById: { type: DataTypes.UUID, allowNull: true },
  },
  {
    sequelize,
    modelName: 'ProjectMember',
    tableName: 'project_members',
    indexes: [
      { unique: true, fields: ['projectId', 'userId'] },
      { fields: ['userId'] },
    ],
  }
);

module.exports = ProjectMember;
