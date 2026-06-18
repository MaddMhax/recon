const express = require('express');
const crypto = require('crypto');
const VulnItem = require('../models/VulnItem');
const User = require('../models/User');
const Referential = require('../models/Referential');
const { getDefaultReferential } = require('../models/Referential');
const { getSsoConfig } = require('../models/SsoConfig');
const { isUuid } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');

const router = express.Router();
router.use(requireAuth, requireAdmin);

// How long a generated password-reset link stays valid.
const RESET_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24h

const CATALOG_ORDER = [['order', 'ASC'], ['code', 'ASC']];

// All vuln operations are scoped to a referential. Resolve it from the request
// (query for GETs/deletes, body for writes), falling back to the default one.
async function resolveReferentialId(req) {
  const id = req.query.referentialId || (req.body && req.body.referentialId);
  if (id && isUuid(id) && (await Referential.findByPk(id))) return id;
  const def = await getDefaultReferential();
  return def ? def.id : null;
}

/* ------------------------------------------------------------------ */
/* Vulnerability catalog (référentiel)                                 */
/* ------------------------------------------------------------------ */

// GET /api/admin/vulns?referentialId=...
router.get('/vulns', async (req, res) => {
  const referentialId = await resolveReferentialId(req);
  const vulns = await VulnItem.findAll({ where: { referentialId }, order: CATALOG_ORDER });
  res.json({ vulns });
});

// POST /api/admin/vulns  (referentialId in body)
router.post('/vulns', async (req, res) => {
  const { code, category, name } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "L'intitulé est requis" });
  }
  const referentialId = await resolveReferentialId(req);
  const vuln = await VulnItem.create({
    referentialId,
    code: (code || '').trim(),
    category: (category || '').trim(),
    name: name.trim(),
    description: req.body.description || '',
    reference: req.body.reference || '',
    command: req.body.command || '',
    notes: req.body.notes || '',
    order: req.body.order || 0,
  });
  res.status(201).json({ vuln });
});

// POST /api/admin/vulns/reorder  — set the catalog display order.
// Body: { ids: [id, id, ...] } in the desired order. Each item's `order` is set
// to its index, which drives the order in new projects' checklists too.
router.post('/vulns/reorder', async (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids : null;
  if (!ids) return res.status(400).json({ error: "Liste d'identifiants attendue" });
  let pos = 0;
  for (const id of ids) {
    if (!isUuid(id)) continue;
    await VulnItem.update({ order: pos }, { where: { id } });
    pos += 1;
  }
  res.json({ ok: true });
});

// PATCH /api/admin/vulns/:id
router.patch('/vulns/:id', async (req, res) => {
  const vuln = isUuid(req.params.id) ? await VulnItem.findByPk(req.params.id) : null;
  if (!vuln) return res.status(404).json({ error: 'Vulnérabilité introuvable' });
  const allowed = ['code', 'category', 'name', 'description', 'reference', 'command', 'notes', 'order'];
  const update = {};
  for (const k of allowed) if (req.body[k] !== undefined) update[k] = req.body[k];
  await vuln.update(update);
  res.json({ vuln });
});

// DELETE /api/admin/vulns?referentialId=...  — wipe one referential's catalog
// (UI requires the admin to type "supprimer" to confirm; export reminder shown).
router.delete('/vulns', async (req, res) => {
  const referentialId = await resolveReferentialId(req);
  const deleted = await VulnItem.destroy({ where: { referentialId } });
  res.json({ deleted });
});

// DELETE /api/admin/vulns/:id
router.delete('/vulns/:id', async (req, res) => {
  const vuln = isUuid(req.params.id) ? await VulnItem.findByPk(req.params.id) : null;
  if (!vuln) return res.status(404).json({ error: 'Vulnérabilité introuvable' });
  await vuln.destroy();
  res.json({ ok: true });
});

// GET /api/admin/vulns/export?referentialId=...  — download one referential as JSON
router.get('/vulns/export', async (req, res) => {
  const referentialId = await resolveReferentialId(req);
  const rows = await VulnItem.findAll({ where: { referentialId }, order: CATALOG_ORDER });
  const vulns = rows.map((v) => ({
    code: v.code,
    category: v.category,
    name: v.name,
    description: v.description,
    reference: v.reference,
    command: v.command,
    notes: v.notes,
    order: v.order,
  }));
  res.setHeader('Content-Disposition', 'attachment; filename="recon-referentiel.json"');
  res.json({ vulns });
});

// POST /api/admin/vulns/import  — bulk import from JSON
// Body: { vulns: [...], mode: 'merge' | 'replace' }
router.post('/vulns/import', async (req, res) => {
  const body = req.body || {};
  const list = Array.isArray(body) ? body : body.vulns;
  const mode = body.mode === 'replace' ? 'replace' : 'merge';
  if (!Array.isArray(list)) {
    return res.status(400).json({ error: 'Format invalide : un tableau "vulns" est attendu' });
  }
  const referentialId = await resolveReferentialId(req);

  if (mode === 'replace') {
    await VulnItem.destroy({ where: { referentialId } });
  }

  let created = 0;
  let updated = 0;
  const errors = [];
  // Coerce every field to a string/number — never trust the JSON shape.
  const str = (v) => (v == null ? '' : String(v));
  for (const raw of list) {
    if (!raw || typeof raw !== 'object' || !str(raw.name).trim()) {
      errors.push({ item: raw, error: "L'intitulé (name) est requis" });
      continue;
    }
    const code = str(raw.code).trim();
    const doc = {
      category: str(raw.category),
      name: str(raw.name),
      description: str(raw.description),
      reference: str(raw.reference),
      command: str(raw.command),
      notes: str(raw.notes),
      order: Number(raw.order) || 0,
    };
    if (code) {
      // Merge by code within this referential.
      const existing = await VulnItem.findOne({ where: { referentialId, code } });
      if (existing) {
        await existing.update(doc);
        updated += 1;
      } else {
        await VulnItem.create({ ...doc, code, referentialId });
        created += 1;
      }
    } else {
      // No code: always insert a new entry.
      await VulnItem.create({ ...doc, code: '', referentialId });
      created += 1;
    }
  }
  res.json({ mode, created, updated, errors });
});

/* ------------------------------------------------------------------ */
/* Referentials (Web / Mobile / Interne / ...)                         */
/* ------------------------------------------------------------------ */

// GET /api/admin/referentials
router.get('/referentials', async (_req, res) => {
  const referentials = await Referential.findAll({ order: [['order', 'ASC'], ['name', 'ASC']] });
  res.json({ referentials });
});

// POST /api/admin/referentials  { name }
router.post('/referentials', async (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  if (!name) return res.status(400).json({ error: 'Le nom du référentiel est requis' });
  if (await Referential.findOne({ where: { name } })) {
    return res.status(409).json({ error: 'Un référentiel porte déjà ce nom' });
  }
  const max = await Referential.max('order');
  const referential = await Referential.create({ name, order: (Number.isFinite(max) ? max : -1) + 1 });
  res.status(201).json({ referential });
});

// PATCH /api/admin/referentials/:id  { name?, isDefault? }
router.patch('/referentials/:id', async (req, res) => {
  const ref = isUuid(req.params.id) ? await Referential.findByPk(req.params.id) : null;
  if (!ref) return res.status(404).json({ error: 'Référentiel introuvable' });
  if (req.body.name !== undefined) {
    const name = String(req.body.name).trim();
    if (!name) return res.status(400).json({ error: 'Le nom du référentiel est requis' });
    const clash = await Referential.findOne({ where: { name } });
    if (clash && clash.id !== ref.id) return res.status(409).json({ error: 'Un référentiel porte déjà ce nom' });
    ref.name = name;
  }
  if (req.body.isDefault === true && !ref.isDefault) {
    await Referential.update({ isDefault: false }, { where: {} });
    ref.isDefault = true;
  }
  await ref.save();
  res.json({ referential: ref });
});

// DELETE /api/admin/referentials/:id  — also removes its vulnerabilities.
router.delete('/referentials/:id', async (req, res) => {
  const ref = isUuid(req.params.id) ? await Referential.findByPk(req.params.id) : null;
  if (!ref) return res.status(404).json({ error: 'Référentiel introuvable' });
  if ((await Referential.count()) <= 1) {
    return res.status(400).json({ error: 'Impossible de supprimer le dernier référentiel' });
  }
  await VulnItem.destroy({ where: { referentialId: ref.id } });
  const wasDefault = ref.isDefault;
  await ref.destroy();
  // Keep exactly one default referential.
  if (wasDefault) {
    const next = await Referential.findOne({ order: [['order', 'ASC'], ['name', 'ASC']] });
    if (next) { next.isDefault = true; await next.save(); }
  }
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/* User management                                                     */
/* ------------------------------------------------------------------ */

// GET /api/admin/users
router.get('/users', async (_req, res) => {
  const users = await User.findAll({ order: [['createdAt', 'ASC']] });
  res.json({ users });
});

// POST /api/admin/users
router.post('/users', async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe sont requis' });
  }
  const exists = await User.findOne({ where: { email: String(email).toLowerCase().trim() } });
  if (exists) return res.status(409).json({ error: 'Cet utilisateur existe déjà' });

  const user = await User.create({
    email: String(email).toLowerCase().trim(),
    passwordHash: await User.hashPassword(password),
    role: role === 'admin' ? 'admin' : 'auditor',
  });
  res.status(201).json({ user });
});

// PATCH /api/admin/users/:id  — change role and/or reset password
router.patch('/users/:id', async (req, res) => {
  const user = isUuid(req.params.id) ? await User.findByPk(req.params.id) : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const update = {};
  if (req.body.role) {
    const role = req.body.role === 'admin' ? 'admin' : 'auditor';
    // Guardrail: an admin cannot remove their own admin role (avoids lockout).
    if (req.params.id === req.user.id && role !== 'admin') {
      return res.status(400).json({ error: 'Vous ne pouvez pas retirer votre propre rôle administrateur' });
    }
    update.role = role;
  }
  if (req.body.password) update.passwordHash = await User.hashPassword(req.body.password);
  await user.update(update);
  res.json({ user });
});

// POST /api/admin/users/:id/reset-link  — issue a secure password-reset link
// to hand to the user. Only the token hash is stored; the raw token is in the
// returned URL and shown to the admin once.
router.post('/users/:id/reset-link', async (req, res) => {
  const user = isUuid(req.params.id) ? await User.findByPk(req.params.id) : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const token = crypto.randomBytes(32).toString('hex');
  user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
  user.resetTokenExpires = new Date(Date.now() + RESET_TOKEN_TTL_MS);
  await user.save();

  const base = `${req.protocol}://${req.get('host')}`;
  const url = `${base}/reset?token=${token}`;
  res.json({ url, email: user.email, expiresAt: user.resetTokenExpires });
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  }
  const user = isUuid(req.params.id) ? await User.findByPk(req.params.id) : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  await user.destroy();
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/* SSO configuration (OAuth2 / OIDC)                                   */
/* ------------------------------------------------------------------ */

// GET /api/admin/sso  — current config (client secret is never returned).
router.get('/sso', async (_req, res) => {
  const sso = await getSsoConfig();
  res.json({ sso });
});

// PUT /api/admin/sso  — update the config. The client secret is only
// overwritten when a non-empty value is supplied (so re-saving the form
// without re-typing the secret keeps the existing one).
router.put('/sso', async (req, res) => {
  const cfg = await getSsoConfig();
  const b = req.body || {};
  const update = {};
  const strFields = ['provider', 'label', 'clientId', 'authorizationUrl', 'tokenUrl', 'userinfoUrl', 'scopes', 'emailField', 'nameField'];
  for (const k of strFields) if (b[k] !== undefined) update[k] = String(b[k]);
  if (b.enabled !== undefined) update.enabled = !!b.enabled;
  if (b.autoCreateUsers !== undefined) update.autoCreateUsers = !!b.autoCreateUsers;
  if (b.defaultRole !== undefined) update.defaultRole = b.defaultRole === 'admin' ? 'admin' : 'auditor';
  if (typeof b.clientSecret === 'string' && b.clientSecret.length) update.clientSecret = b.clientSecret;
  await cfg.update(update);
  res.json({ sso: cfg });
});

// Fetch a URL with a hard timeout; never throws — returns a normalized result.
async function probe(url, init = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 6000);
  try {
    // redirect: 'manual' so a 3xx is reported as-is (a discovery/auth URL that
    // redirects is usually a misconfiguration, not a success).
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, ...init });
    return { status: res.status, res };
  } catch (err) {
    return { error: err.name === 'AbortError' ? 'délai dépassé' : (err.cause?.code || err.message) };
  } finally {
    clearTimeout(timer);
  }
}

// POST /api/admin/sso/test  — check that the configured endpoints are reachable
// and (when possible) that the client id/secret are accepted by the token
// endpoint. Tests the supplied form values, falling back to the stored secret
// when the secret field is left blank (same rule as PUT).
router.post('/sso/test', async (req, res) => {
  const cfg = await getSsoConfig();
  const b = req.body || {};
  const pick = (k) => (typeof b[k] === 'string' && b[k].length ? b[k] : cfg[k]);
  const authorizationUrl = pick('authorizationUrl');
  const tokenUrl = pick('tokenUrl');
  const userinfoUrl = pick('userinfoUrl');
  const clientId = pick('clientId');
  const clientSecret = typeof b.clientSecret === 'string' && b.clientSecret.length ? b.clientSecret : cfg.clientSecret;

  const checks = [];

  // 1) Authorization URL — probe with the real authorization-code parameters.
  //    A bare GET just yields HTTP 400 ("missing client_id") even on a perfectly
  //    valid endpoint, so send the same params the login flow uses: the provider
  //    then renders its login page (200) or redirects to it (302) when the
  //    client_id and redirect_uri are correct, and returns an error otherwise —
  //    which also catches an unregistered redirect URI.
  if (!authorizationUrl) {
    checks.push({ name: "URL d'autorisation", ok: false, message: 'Non renseignée' });
  } else if (!clientId) {
    checks.push({ name: "URL d'autorisation", ok: false, message: 'Client ID non renseigné' });
  } else {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: `${req.protocol}://${req.get('host')}/api/auth/sso/callback`,
      scope: pick('scopes') || 'openid email profile',
      state: 'sso-test',
    });
    const r = await probe(`${authorizationUrl}?${params.toString()}`);
    if (r.error) checks.push({ name: "URL d'autorisation", ok: false, message: `Injoignable (${r.error})` });
    else if (r.status === 200 || r.status === 302) checks.push({ name: "URL d'autorisation", ok: true, message: `HTTP ${r.status} — page de connexion accessible` });
    else checks.push({ name: "URL d'autorisation", ok: false, message: `HTTP ${r.status} — vérifiez le Client ID et l'URI de redirection` });
  }

  // 2) Token URL — validate the client credentials with a client_credentials grant.
  //    invalid_client = bad id/secret; unauthorized_client/unsupported_grant_type
  //    = credentials accepted but the grant is disabled (still proves the secret).
  if (!tokenUrl) {
    checks.push({ name: 'URL de jeton + identifiants client', ok: false, message: 'URL de jeton non renseignée' });
  } else if (!clientId) {
    checks.push({ name: 'URL de jeton + identifiants client', ok: false, message: 'Client ID non renseigné' });
  } else {
    const r = await probe(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret || '' }),
    });
    if (r.error) {
      checks.push({ name: 'URL de jeton + identifiants client', ok: false, message: `Injoignable (${r.error})` });
    } else {
      let err = null;
      try { err = (await r.res.json()).error; } catch (_) { /* non-JSON body */ }
      if (r.status === 200) checks.push({ name: 'URL de jeton + identifiants client', ok: true, message: 'Identifiants acceptés (jeton obtenu)' });
      else if (err === 'invalid_client' || r.status === 401) checks.push({ name: 'URL de jeton + identifiants client', ok: false, message: 'Identifiants client refusés (invalid_client) — vérifiez le Client Secret' });
      else if (err === 'unauthorized_client' || err === 'unsupported_grant_type' || err === 'invalid_grant') checks.push({ name: 'URL de jeton + identifiants client', ok: true, message: `Identifiants acceptés (grant client_credentials désactivé : ${err})` });
      else checks.push({ name: 'URL de jeton + identifiants client', ok: false, message: `HTTP ${r.status}${err ? ` (${err})` : ''}` });
    }
  }

  // 3) Userinfo URL — should be reachable and require a token (401 is expected/healthy).
  if (!userinfoUrl) {
    checks.push({ name: 'URL userinfo', ok: false, message: 'Non renseignée' });
  } else {
    const r = await probe(userinfoUrl);
    if (r.error) checks.push({ name: 'URL userinfo', ok: false, message: `Injoignable (${r.error})` });
    else if (r.status === 401 || r.status === 403) checks.push({ name: 'URL userinfo', ok: true, message: `HTTP ${r.status} — joignable (jeton requis)` });
    else checks.push({ name: 'URL userinfo', ok: r.status < 400, message: `HTTP ${r.status}` });
  }

  res.json({ checks, ok: checks.every((c) => c.ok) });
});

module.exports = router;
