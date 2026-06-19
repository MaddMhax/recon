const User = require('./models/User');
const VulnItem = require('./models/VulnItem');
const Referential = require('./models/Referential');
const Project = require('./models/Project');
const { sequelize } = require('./config/db');
const { getChecklistTemplate } = require('./data/wstgTemplate');

// Idempotent bootstrap run at startup:
//  - creates the admin account if it does not exist
//  - creates the default referentials (Web / Mobile / Interne) if none exist
//  - backfills any pre-referential vulns into the default ("Web") referential
//  - populates the "Web" referential from the WSTG template if it is empty
async function runSeed() {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@local').toLowerCase().trim();
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin1234';

  const existingAdmin = await User.findOne({ where: { email: adminEmail } });
  if (!existingAdmin) {
    await User.create({
      email: adminEmail,
      passwordHash: await User.hashPassword(adminPassword),
      role: 'admin',
    });
    console.log(`[seed] admin account created: ${adminEmail}`);
  }

  // Referentials — "Web" is the default and ships the WSTG catalog; "Mobile"
  // and "Interne" start empty for admins to populate.
  if ((await Referential.count()) === 0) {
    await Referential.bulkCreate([
      { name: 'Web', isDefault: true, order: 0 },
      { name: 'Mobile', isDefault: false, order: 1 },
      { name: 'Interne', isDefault: false, order: 2 },
    ]);
    console.log('[seed] referentials created: Web (default), Mobile, Interne');
  }

  const web = (await Referential.findOne({ where: { name: 'Web' } })) ||
    (await Referential.findOne({ where: { isDefault: true } }));

  // Backfill: attach any vuln created before referentials existed to "Web".
  if (web) {
    await sequelize.query('UPDATE "vuln_items" SET "referentialId" = :id WHERE "referentialId" IS NULL', {
      replacements: { id: web.id },
    });
  }

  // Seed the WSTG catalog into "Web" only if that referential is still empty.
  if (web && (await VulnItem.count({ where: { referentialId: web.id } })) === 0) {
    const template = getChecklistTemplate();
    const docs = template.map((t, i) => ({
      referentialId: web.id,
      code: t.code,
      category: t.category,
      name: t.name,
      description: t.description,
      reference: t.reference,
      command: t.command || '',
      notes: t.notes || '',
      order: i,
    }));
    await VulnItem.bulkCreate(docs);
    console.log(`[seed] "Web" referential seeded with ${docs.length} items`);
  }

  // Backfill share tokens onto projects created before the column existed, so
  // every project has a shareable deep link.
  const slugless = await Project.findAll({ where: { shareSlug: null } });
  for (const p of slugless) {
    p.shareSlug = Project.genShareSlug();
    await p.save();
  }
  if (slugless.length) {
    console.log(`[seed] backfilled share links for ${slugless.length} project(s)`);
  }
}

module.exports = { runSeed };
