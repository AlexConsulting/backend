// routes/profileRoutes.js
// Profile update (name change)

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
// UPDATE USER NAME
// =============================
router.post('/update', auth, (req, res) => {
  const { name } = req.body;
  if (!name || name.length < 2)
    return res.json({ success: false });

  db.updateUserName(req.user_id, name, (err) => {
    if (err) return res.json({ success: false });
    res.json({ success: true });
  });
});

module.exports = router;