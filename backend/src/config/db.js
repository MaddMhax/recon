const { Sequelize } = require('sequelize');

// Single shared Sequelize instance for the whole app. Connection string comes
// from DATABASE_URL, e.g. postgres://user:pass@db:5432/recon
const url = process.env.DATABASE_URL;
if (!url) {
  throw new Error('DATABASE_URL is not set');
}

const sequelize = new Sequelize(url, {
  dialect: 'postgres',
  logging: false, // set to console.log to debug SQL
});

// Guard against passing a non-UUID id to findByPk — Postgres would raise
// "invalid input syntax for type uuid" (a 500). We want a clean 404 instead,
// so callers can check this first and treat a bad id as "not found".
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

async function connectDB() {
  // Retry loop — the app container can start before Postgres is ready to accept
  // connections even with depends_on/healthcheck in place.
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await sequelize.authenticate();
      // Create any missing tables. The schema is small and additive, so plain
      // sync() (create-if-not-exists, no destructive alters) keeps deployment
      // simple — there is no separate migration step to run.
      await sequelize.sync();
      // Idempotent additive migrations for columns introduced after the initial
      // release (sync() does not alter existing tables). Safe to run every boot.
      await sequelize.query('ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "ssoProvider" VARCHAR');
      await sequelize.query('ALTER TABLE "vuln_items" ADD COLUMN IF NOT EXISTS "referentialId" UUID');
      await sequelize.query('ALTER TABLE "projects" ADD COLUMN IF NOT EXISTS "referentialId" UUID');
      // Shareable per-project deep-link token. The unique index tolerates the
      // NULLs left on existing rows until seed.js backfills them.
      await sequelize.query('ALTER TABLE "projects" ADD COLUMN IF NOT EXISTS "shareSlug" VARCHAR(16)');
      await sequelize.query('CREATE UNIQUE INDEX IF NOT EXISTS "projects_shareSlug_uniq" ON "projects" ("shareSlug")');
      console.log('[db] connected to PostgreSQL');
      return;
    } catch (err) {
      console.warn(`[db] connection attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
      if (attempt === maxAttempts) throw err;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}

module.exports = { sequelize, connectDB, isUuid };
