const User = require('./models/User');
const VulnItem = require('./models/VulnItem');
const { getChecklistTemplate } = require('./data/wstgTemplate');

// Idempotent bootstrap run at startup:
//  - creates the admin account if it does not exist
//  - populates the vulnerability catalog from the WSTG template if empty
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

  const count = await VulnItem.count();
  if (count === 0) {
    const template = getChecklistTemplate();
    const docs = template.map((t, i) => ({
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
    console.log(`[seed] vulnerability catalog seeded with ${docs.length} items`);
  }
}

module.exports = { runSeed };
