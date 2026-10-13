const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/db');

// Single-row SSO (OAuth2 / OIDC) configuration managed from the admin panel.
// The client secret is stored but NEVER serialized — toJSON exposes only a
// `hasSecret` flag so the admin UI can show whether one is set.
class SsoConfig extends Model {
  toJSON() {
    const v = this.get({ plain: true });
    return {
      _id: v.id,
      enabled: v.enabled,
      provider: v.provider,
      label: v.label,
      clientId: v.clientId,
      hasSecret: !!v.clientSecret,
      authorizationUrl: v.authorizationUrl,
      tokenUrl: v.tokenUrl,
      userinfoUrl: v.userinfoUrl,
      scopes: v.scopes,
      emailField: v.emailField,
      nameField: v.nameField,
      autoCreateUsers: v.autoCreateUsers,
      trustUnverifiedEmail: v.trustUnverifiedEmail,
      updatedAt: v.updatedAt,
    };
  }

  // True when the config has the minimum needed to start an SSO login.
  isUsable() {
    return !!(this.enabled && this.clientId && this.authorizationUrl && this.tokenUrl && this.userinfoUrl);
  }
}

SsoConfig.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    // google | github | gitlab | keycloak | microsoft | custom
    provider: { type: DataTypes.STRING, allowNull: false, defaultValue: 'custom' },
    label: { type: DataTypes.STRING, allowNull: false, defaultValue: 'Se connecter via SSO' },
    clientId: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    clientSecret: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    authorizationUrl: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    tokenUrl: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    userinfoUrl: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    scopes: { type: DataTypes.STRING, allowNull: false, defaultValue: 'openid email profile' },
    // Field names to read from the userinfo response.
    emailField: { type: DataTypes.STRING, allowNull: false, defaultValue: 'email' },
    nameField: { type: DataTypes.STRING, allowNull: false, defaultValue: 'name' },
    // Provision a new local account on first SSO login (otherwise the email must
    // already exist). New accounts are always auditors.
    autoCreateUsers: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    // Legacy column, no longer used (provisioned accounts are always auditors).
    defaultRole: { type: DataTypes.ENUM('admin', 'auditor'), allowNull: false, defaultValue: 'auditor' },
    // Accept e-mails the provider does not mark as verified (e.g. Microsoft
    // Entra sends no email_verified). Off by default: with it, whoever can set
    // an address at the provider can claim the matching non-admin account.
    trustUnverifiedEmail: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  },
  {
    sequelize,
    modelName: 'SsoConfig',
    tableName: 'sso_config',
  }
);

// Fetch the singleton config row, creating defaults on first use.
async function getSsoConfig() {
  let cfg = await SsoConfig.findOne();
  if (!cfg) cfg = await SsoConfig.create({});
  return cfg;
}

module.exports = SsoConfig;
module.exports.getSsoConfig = getSsoConfig;
