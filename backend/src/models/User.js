const { DataTypes, Model } = require('sequelize');
const bcrypt = require('bcryptjs');
const { sequelize } = require('../config/db');

class User extends Model {
  verifyPassword(plain) {
    return bcrypt.compare(plain, this.passwordHash);
  }

  static hashPassword(plain) {
    return bcrypt.hash(plain, 10);
  }

  // Never leak the hash, reset secrets or the raw avatar bytes through JSON.
  // Expose `_id` (for frontend compatibility) and a lightweight `hasAvatar`.
  toJSON() {
    const v = this.get({ plain: true });
    return {
      _id: v.id,
      email: v.email,
      role: v.role,
      color: v.color,
      hasAvatar: !!v.avatarData,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
    };
  }
}

User.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      set(val) {
        this.setDataValue('email', String(val).toLowerCase().trim());
      },
    },
    passwordHash: { type: DataTypes.STRING, allowNull: false },
    role: {
      type: DataTypes.ENUM('admin', 'auditor'),
      allowNull: false,
      defaultValue: 'auditor',
    },
    // Profile customisation. "#RRGGBB" or null (fallback color).
    color: { type: DataTypes.STRING, allowNull: true, defaultValue: null },
    // Avatar stored in the DB (no filesystem). Only validated PNG/JPEG bytes.
    avatarData: { type: DataTypes.BLOB, allowNull: true, defaultValue: null },
    avatarType: { type: DataTypes.STRING, allowNull: true, defaultValue: null },
    // Password reset via secure link: only the SHA-256 hash of the token is
    // stored, with an expiry. The raw token lives only in the link.
    resetTokenHash: { type: DataTypes.STRING, allowNull: true, defaultValue: null },
    resetTokenExpires: { type: DataTypes.DATE, allowNull: true, defaultValue: null },
  },
  {
    sequelize,
    modelName: 'User',
    tableName: 'users',
  }
);

module.exports = User;
