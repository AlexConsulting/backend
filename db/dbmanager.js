// db/dbmanager.js
// SQLite manager for SOC Analyzer SaaS
// Handles: users, plans, history, quota, password reset tokens

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'soc.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('SQLite open error:', err);
  else console.log('SQLite DB ready at', dbPath);
});

// Initialize tables
db.serialize(() => {
  // users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan_id INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    reset_token TEXT,
    reset_expire INTEGER
  )`);

  // plans
  db.run(`CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    quota INTEGER NOT NULL
  )`);

  // ensure default plans
  db.run(`INSERT OR IGNORE INTO plans (id,name,quota) VALUES (1,'FREE',15)`);
  db.run(`INSERT OR IGNORE INTO plans (id,name,quota) VALUES (2,'BASIC',50)`);
  db.run(`INSERT OR IGNORE INTO plans (id,name,quota) VALUES (3,'PRO',100)`);
  db.run(`INSERT OR IGNORE INTO plans (id,name,quota) VALUES (4,'ENTERPRISE',250)`);

  // history
  db.run(`CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    query TEXT,
    type TEXT,
    result TEXT
  )`);

  // quota_usage
  db.run(`CREATE TABLE IF NOT EXISTS quota_usage (
    user_id INTEGER PRIMARY KEY,
    used INTEGER DEFAULT 0
  )`);

  // password_resets (optional separate tracking)
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ----------------------
// User functions
// ----------------------
module.exports.createUser = (name, email, hash, cb) => {
  const stmt = db.prepare(`INSERT INTO users (name,email,password_hash) VALUES (?,?,?)`);
  stmt.run([name, email, hash], function (err) {
    if (cb) cb(err, this && this.lastID);
  });
};

module.exports.getUserByEmail = (email, cb) => {
  db.get(`SELECT * FROM users WHERE email = ?`, [email], cb);
};

module.exports.getUserById = (id, cb) => {
  db.get(`SELECT * FROM users WHERE id = ?`, [id], cb);
};

module.exports.updateLastLogin = (id) => {
  db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [id]);
};

module.exports.updateUserName = (id, name, cb) => {
  db.run(`UPDATE users SET name = ? WHERE id = ?`, [name, id], function (err) {
    if (cb) cb && cb(err);
  });
};

module.exports.updateUserPassword = (id, hash, cb) => {
  db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [hash, id], function (err) {
    if (cb) cb && cb(err);
  });
};

// ----------------------
// Password reset token helpers (two approaches present; both usable)
// ----------------------
module.exports.setResetToken = (email, token, expire, cb) => {
  // store in users table for backward compatibility
  db.run(`UPDATE users SET reset_token = ?, reset_expire = ? WHERE email = ?`, [token, expire, email], function (err) {
    if (cb) cb && cb(err);
  });
};

module.exports.getUserByResetToken = (token, cb) => {
  const now = Date.now();
  // try users.reset_token first
  db.get(`SELECT * FROM users WHERE reset_token = ? AND reset_expire > ?`, [token, now], (err, row) => {
    if (err) return cb(err);
    if (row) return cb(null, row);
    // fallback to password_resets table
    db.get(`SELECT user_id, token, expires_at FROM password_resets WHERE token = ? AND expires_at > ?`, [token, new Date().toISOString()], (e, r) => {
      if (e) return cb(e);
      if (!r) return cb(null, null);
      // fetch user by id
      db.get(`SELECT * FROM users WHERE id = ?`, [r.user_id], cb);
    });
  });
};

module.exports.clearResetToken = (id, cb) => {
  db.run(`UPDATE users SET reset_token = NULL, reset_expire = NULL WHERE id = ?`, [id], function (err) {
    if (cb) cb && cb(err);
  });
};

// ----------------------
// Plans
// ----------------------
module.exports.getPlans = (cb) => {
  db.all(`SELECT * FROM plans ORDER BY id ASC`, [], cb);
};

module.exports.getPlanById = (id, cb) => {
  db.get(`SELECT * FROM plans WHERE id = ?`, [id], cb);
};

module.exports.setUserPlan = (user_id, plan_id, cb) => {
  db.run(`UPDATE users SET plan_id = ? WHERE id = ?`, [plan_id, user_id], function (err) {
    if (cb) cb && cb(err);
  });
};

// ----------------------
// Quota
// ----------------------
module.exports.getQuota = (user_id, cb) => {
  db.get(`SELECT used FROM quota_usage WHERE user_id = ?`, [user_id], (err, row) => {
    if (err) return cb(err);
    const used = row ? row.used : 0;
    cb(null, used);
  });
};

// incrementQuota / increment usage by 1
module.exports.incrementQuota = (user_id, cb) => {
  // Try insert, otherwise update
  db.run(`INSERT INTO quota_usage (user_id, used) VALUES (?, 1)
          ON CONFLICT(user_id) DO UPDATE SET used = used + 1`, [user_id], function (err) {
    if (cb) cb && cb(err);
  });
};

module.exports.resetQuota = (user_id, cb) => {
  db.run(`UPDATE quota_usage SET used = 0 WHERE user_id = ?`, [user_id], function (err) {
    if (cb) cb && cb(err);
  });
};

// ----------------------
// History
// ----------------------
module.exports.addHistory = (user_id, query, type, result, cb) => {
  // timestamp as epoch ms
  const ts = Date.now();
  db.run(`INSERT INTO history (user_id, timestamp, query, type, result) VALUES (?, ?, ?, ?, ?)`,
    [user_id, ts, query, type, result],
    function (err) {
      if (cb) cb && cb(err, this && this.lastID);
    });
};

module.exports.getHistory = (user_id, cb) => {
  db.all(`SELECT * FROM history WHERE user_id = ? ORDER BY timestamp DESC`, [user_id], cb);
};

module.exports.getHistoryItem = (user_id, id, cb) => {
  db.get(`SELECT * FROM history WHERE id = ? AND user_id = ?`, [id, user_id], cb);
};

// Export raw db object for ad-hoc queries if needed
module.exports.db = db;
