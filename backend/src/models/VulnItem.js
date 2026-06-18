const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/db');

// Master catalog of vulnerabilities ("référentiel"). Admins manage this list
// from the /admin area. When a project is created, a snapshot of this catalog
// is copied into the project's own checklist.
class VulnItem extends Model {
  toJSON() {
    const v = this.get({ plain: true });
    return {
      _id: v.id,
      code: v.code,
      category: v.category,
      name: v.name,
      description: v.description,
      reference: v.reference,
      command: v.command,
      notes: v.notes,
      order: v.order,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
    };
  }
}

VulnItem.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    code: { type: DataTypes.STRING, allowNull: false, defaultValue: '' }, // optional, e.g. WSTG-ATHN-01
    category: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    name: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    reference: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    command: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    notes: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    // "order" is a reserved SQL word — store it in column `sort_order`.
    order: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0, field: 'sort_order' },
  },
  {
    sequelize,
    modelName: 'VulnItem',
    tableName: 'vuln_items',
  }
);

module.exports = VulnItem;
