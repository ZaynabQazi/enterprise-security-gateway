require('./config/env');
const db = require('./config/db');
const { seedDemoUsers } = require('./utils/seedUsers');

(async () => {
  await db.init();
  await seedDemoUsers();
  await db.close();
  console.log('Seeding done.');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
