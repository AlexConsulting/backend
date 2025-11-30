// routes/quotaRoutes.js
// Returns current quota usage and limit

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
// CURRENT QUOTA
// =============================
router.get('/current', auth, (req, res) => {
  db.getUserById(req.user_id, (err, user) => {
    if (err || !user) return res.status(401).json({});

    db.getPlanById(user.plan_id, (err, plan) => {
      if (err || !plan) return res.json({});

      db.getQuota(req.user_id, (err, used) => {
        if (err) return res.json({});
        res.json({ used, limit: plan.quota });
      });
    });
  });
});

module.exports = router;