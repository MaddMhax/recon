const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/db');

// A named catalog of vulnerabilities (e.g. "Web", "Mobile", "Interne"). Each
// VulnItem belongs to one referential; a project snapshots one referential's
// items into its checklist when created.
class Referential extends Model {
  toJSON() {
    const v = this.get({ plain: true });
    return {
      _id: v.id,
      name: v.name,
      isDefault: v.isDefault,
      order: v.order,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
    };
  }
}

Referential.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false, unique: true },
    isDefault: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    order: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0, field: 'sort_order' },
  },
  {
    sequelize,
    modelName: 'Referential',
    tableName: 'referentials',
  }
);

// The referential a new project defaults to (the one flagged default, else the
// first by order). Returns null only when none exist (before seeding).
async function getDefaultReferential() {
  return (
    (await Referential.findOne({ where: { isDefault: true } })) ||
    (await Referential.findOne({ order: [['order', 'ASC'], ['name', 'ASC']] }))
  );
}

module.exports = Referential;
module.exports.getDefaultReferential = getDefaultReferential;
