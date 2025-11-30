// routes/historyRoutes.js
// History listing and item details

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
// FULL HISTORY LIST
// =============================
router.get('/list', auth, (req, res) => {
  db.getHistory(req.user_id, (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

// =============================
// SINGLE HISTORY ITEM
// =============================
router.get('/item', auth, (req, res) => {
  const { id } = req.query;
  if (!id) return res.json({});

  db.getHistoryItem(req.user_id, id, (err, row) => {
    if (err || !row) return res.json({});
    res.json(row);
  });
});

module.exports = router;