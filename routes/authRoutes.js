// routes/authRoutes.js
// Authentication routes for SOC Analyzer SaaS

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../db/dbmanager');
const path = require('path');
const winston = require('winston');

// ======================================================
// LOGGER WINSTON (SEM REMOVER NADA DO CÓDIGO ORIGINAL)
// ======================================================
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, "../logs/app.log")
    }),
    new winston.transports.Console()
  ]
});

// ======================================================
// LOGIN
// ======================================================
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  logger.info(`[LOGIN ATTEMPT] Email: ${email}`);

  if (!email || !password) {
    logger.warn(`[LOGIN FAIL] Dados incompletos — Email: ${email}`);
    return res.status(401).json({ success: false, msg: 'Dados incompletos' });
  }

  db.getUserByEmail(email, async (err, user) => {
    if (err) {
      logger.error(`[LOGIN ERROR] Erro DB ao buscar ${email}`);
      return res.json({ success: false });
    }

    if (!user) {
      logger.warn(`[LOGIN FAIL] Usuário não encontrado: ${email}`);
      return res.status(401).json({ success: false, msg: 'Usuário não encontrado' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      logger.warn(`[LOGIN FAIL] Senha incorreta para ${email}`);
      return res.status(401).json({ success: false, msg: 'Senha incorreta' });
    }

    logger.info(`[LOGIN SUCCESS] Usuário autenticado: ${email}`);

    db.updateLastLogin(user.id);
    res.cookie('user_id', user.id, { httpOnly: true, sameSite: 'strict' });
    res.json({ success: true });
  });
});

// ======================================================
// LOGOUT
// ======================================================
router.post('/logout', (req, res) => {
  const uid = req.cookies.user_id;

  logger.info(`[LOGOUT] Usuario ID: ${uid || "desconhecido"}`);

  res.clearCookie('user_id');
  res.json({ success: true });
});

// ======================================================
// REGISTER
// ======================================================
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  logger.info(`[REGISTER ATTEMPT] Email: ${email}`);

  if (!name || !email || !password) {
    logger.warn(`[REGISTER FAIL] Dados incompletos — Email: ${email}`);
    return res.json({ success: false });
  }

  const hash = await bcrypt.hash(password, 10);

  db.createUser(name, email, hash, (err, id) => {
    if (err) {
      logger.warn(`[REGISTER FAIL] Email já cadastrado: ${email}`);
      return res.json({ success: false, msg: 'Email já cadastrado' });
    }

    logger.info(`[REGISTER SUCCESS] Novo usuário criado: ${email}`);
    res.json({ success: true });
  });
});

// ======================================================
// SESSION
// ======================================================
router.get('/session', (req, res) => {
  const uid = req.cookies.user_id;

  logger.info(`[SESSION CHECK] UID: ${uid}`);

  if (!uid) return res.status(401).json({});

  db.getUserById(uid, (err, user) => {
    if (err || !user) {
      logger.warn(`[SESSION INVALID] UID: ${uid}`);
      return res.status(401).json({});
    }

    logger.info(`[SESSION OK] UID: ${uid}`);
    res.json(user);
  });
});

// ======================================================
// CHANGE PASSWORD (LOGGED IN)
// ======================================================
router.post('/password/change', async (req, res) => {
  const uid = req.cookies.user_id;
  const { password } = req.body;

  logger.info(`[PASSWORD CHANGE ATTEMPT] UID: ${uid}`);

  if (!uid)
    return res.status(401).json({ success: false });

  if (!password || password.length < 8) {
    logger.warn(`[PASSWORD CHANGE FAIL] Senha inválida — UID: ${uid}`);
    return res.json({ success: false });
  }

  const hash = await bcrypt.hash(password, 10);

  db.updateUserPassword(uid, hash, (err) => {
    if (err) {
      logger.error(`[PASSWORD CHANGE ERROR] UID: ${uid}`);
      return res.json({ success: false });
    }

    logger.info(`[PASSWORD CHANGE SUCCESS] UID: ${uid}`);
    res.json({ success: true });
  });
});

// ======================================================
// FORGOT PASSWORD
// ======================================================
router.post('/password/forgot', (req, res) => {
  const { email } = req.body;

  logger.info(`[FORGOT PASSWORD] Email: ${email}`);

  db.getUserByEmail(email, (err, user) => {
    if (err || !user) {
      logger.warn(`[FORGOT PASSWORD IGNORE] Email não encontrado: ${email}`);
      return res.json({ success: true });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expire = Date.now() + 1000 * 60 * 30; // 30min

    db.setResetToken(email, token, expire, () => {
      logger.info(`[RESET TOKEN GENERATED] Email: ${email} — Token: ${token}`);
      res.json({ success: true, token });
    });
  });
});

// ======================================================
// RESET PASSWORD
// ======================================================
router.post('/password/reset', async (req, res) => {
  const { token, password } = req.body;

  logger.info(`[PASSWORD RESET ATTEMPT] Token: ${token}`);

  if (!token || !password)
    return res.json({ success: false });

  db.getUserByResetToken(token, async (err, user) => {
    if (err || !user) {
      logger.warn(`[PASSWORD RESET FAIL] Token inválido`);
      return res.json({ success: false });
    }

    const hash = await bcrypt.hash(password, 10);

    db.updateUserPassword(user.id, hash, () => {
      db.clearResetToken(user.id);

      logger.info(`[PASSWORD RESET SUCCESS] User ID: ${user.id}`);

      res.json({ success: true });
    });
  });
});

module.exports = router;
