// routes/authRoutes.js
// Authentication routes for SOC Analyzer SaaS

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../db/dbmanager');

// =============================
// LOGIN
// =============================
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, msg: 'Dados incompletos' });

  db.getUserByEmail(email, async (err, user) => {
    if (err) return res.json({ success: false });
    if (!user) return res.json({ success: false, msg: 'Usuário não encontrado' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ success: false, msg: 'Senha incorreta' });

    // login ok
    db.updateLastLogin(user.id);
    res.cookie('user_id', user.id, { httpOnly: true, sameSite: 'strict' });
    res.json({ success: true });
  });
});

// =============================
// LOGOUT
// =============================
router.post('/logout', (req, res) => {
  res.clearCookie('user_id');
  res.json({ success: true });
});

// =============================
// REGISTER
// =============================
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.json({ success: false });

  const hash = await bcrypt.hash(password, 10);

  db.createUser(name, email, hash, (err, id) => {
    if (err) return res.json({ success: false, msg: 'Email já cadastrado' });
    res.json({ success: true });
  });
});

// =============================
// SESSION
// =============================
router.get('/session', (req, res) => {
  const uid = req.cookies.user_id;
  if (!uid) return res.status(401).json({});

  db.getUserById(uid, (err, user) => {
    if (err || !user) return res.status(401).json({});
    res.json(user);
  });
});

// =============================
// CHANGE PASSWORD (LOGGED IN)
// =============================
router.post('/password/change', async (req, res) => {
  const uid = req.cookies.user_id;
  if (!uid) return res.status(401).json({ success: false });

  const { password } = req.body;
  if (!password || password.length < 8)
    return res.json({ success: false });

  const hash = await bcrypt.hash(password, 10);
  db.updateUserPassword(uid, hash, (err) => {
    if (err) return res.json({ success: false });
    res.json({ success: true });
  });
});

// =============================
// FORGOT PASSWORD
// =============================
router.post('/password/forgot', (req, res) => {
  const { email } = req.body;

  db.getUserByEmail(email, (err, user) => {
    if (err || !user) return res.json({ success: true });

    const token = crypto.randomBytes(32).toString('hex');
    const expire = Date.now() + 1000 * 60 * 30; // 30min

    db.setResetToken(email, token, expire, () => {
      // Here we will integrate email sending later
      res.json({ success: true, token });
    });
  });
});

// =============================
// RESET PASSWORD
// =============================
router.post('/password/reset', async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password)
    return res.json({ success: false });

  db.getUserByResetToken(token, async (err, user) => {
    if (err || !user) return res.json({ success: false });

    const hash = await bcrypt.hash(password, 10);

    db.updateUserPassword(user.id, hash, () => {
      db.clearResetToken(user.id);
      res.json({ success: true });
    });
  });
});

module.exports = router;