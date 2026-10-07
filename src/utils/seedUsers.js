const bcrypt = require('bcryptjs');
const User = require('../models/User');

// Demo accounts listed in the README. Only the bcrypt hash is stored.
const DEMO_USERS = [
  { name: 'Super Admin', email: 'superadmin@gateway.test', password: 'SuperAdmin@123', role: 'SuperAdmin' },
  { name: 'Mina Manager', email: 'manager@gateway.test', password: 'Manager@123', role: 'Manager' },
  { name: 'Eli Employee', email: 'employee@gateway.test', password: 'Employee@123', role: 'Employee' },
];

async function seedDemoUsers() {
  for (const u of DEMO_USERS) {
    const exists = await User.findByEmail(u.email);
    if (exists) continue;
    await User.create({
      name: u.name,
      email: u.email,
      role: u.role,
      passwordHash: await bcrypt.hash(u.password, 12),
      isLocal: true,
    });
    console.log(`Seeded ${u.role}: ${u.email}`);
  }
}

module.exports = { seedDemoUsers, DEMO_USERS };
