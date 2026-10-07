const express = require('express');
const User = require('../models/User');
const { authenticate, checkRole } = require('../middleware/auth');

const router = express.Router();

// User ids are positive integers (MySQL AUTO_INCREMENT). Anything else is rejected before touching the DB.
function parseId(value) {
  const s = String(value);
  if (!/^\d{1,10}$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

// GET /api/v1/employee/profile -> every authenticated role
router.get('/employee/profile', authenticate, checkRole(['SuperAdmin', 'Manager', 'Employee']), (req, res) => {
  res.json({ profile: User.toSafeJSON(req.user) });
});

// POST /api/v1/payroll/approve -> Manager and SuperAdmin only
router.post('/payroll/approve', authenticate, checkRole(['Manager', 'SuperAdmin']), async (req, res, next) => {
  try {
    const { employeeId, amount, period } = req.body || {};
    const id = parseId(employeeId);
    if (id === null) {
      return res.status(400).json({ error: 'employeeId must be a valid user id (a positive whole number)' });
    }
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }
    if (typeof period !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])$/.test(period)) {
      return res.status(400).json({ error: 'period must look like YYYY-MM' });
    }

    // Multi-tenant check: approvers can only act inside their own tenant
    const employee = await User.findInTenant(id, req.user.tenantId);
    if (!employee) return res.status(404).json({ error: 'Employee not found in your tenant' });

    res.json({
      message: 'Payroll approved',
      approval: {
        employee: { id: employee.id, name: employee.name },
        amount,
        period,
        approvedBy: { id: req.user.id, name: req.user.name, role: req.user.role },
        approvedAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/users -> SuperAdmin only (handy for finding ids to delete)
router.get('/users', authenticate, checkRole(['SuperAdmin']), async (req, res, next) => {
  try {
    const users = await User.listByTenant(req.user.tenantId);
    res.json({ users: users.map(User.toSafeJSON) });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/v1/users/:id -> SuperAdmin only
router.delete('/users/:id', authenticate, checkRole(['SuperAdmin']), async (req, res, next) => {
  try {
    const id = parseId(req.params.id);
    if (id === null) return res.status(400).json({ error: 'Invalid user id' });
    if (req.user.id === id) return res.status(400).json({ error: 'You cannot delete your own account' });

    const deleted = await User.deleteInTenant(id, req.user.tenantId); // also deletes their refresh tokens
    if (!deleted) return res.status(404).json({ error: 'User not found' });

    res.json({ message: 'User deleted', id });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
