// routes/plansRoutes.js
// Plan listing, current plan and upgrade

const express = require('express');
const router = express.Router();
const db = require('../db/dbmanager');

// Middleware: require login
function auth(req, res, next) {
  const uid = req.cookies.user_id;
  if (!uid) return res.status(401).json({});
  req.user_id = uid;
  next();
}

// =============================
// LIST ALL PLANS
// =============================
router.get('/list', (req, res) => {
  db.getPlans((err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

// =============================
// CURRENT USER PLAN
// =============================
router.get('/current', auth, (req, res) => {
  db.getUserById(req.user_id, (err, user) => {
    if (err || !user) return res.status(401).json({});

    db.getPlanById(user.plan_id, (err, plan) => {
      if (err || !plan) return res.json({});
      res.json({ plan_id: plan.id, plan_name: plan.name, quota: plan.quota });
    });
  });
});

// =============================
// UPGRADE PLAN
// =============================
router.post('/upgrade', auth, (req, res) => {
  const { plan_id } = req.body;
  if (!plan_id) return res.json({ success: false });

  db.getPlanById(plan_id, (err, plan) => {
    if (err || !plan) return res.json({ success: false });

    db.setUserPlan(req.user_id, plan_id, (err) => {
      if (err) return res.json({ success: false });
      res.json({ success: true });
    });
  });
});

module.exports = router;