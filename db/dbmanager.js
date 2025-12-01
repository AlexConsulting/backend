// db/dbmanager.js
// PostgreSQL manager for SOC Analyzer SaaS
// Same API as the SQLite version, but using pg + SQL compatible with PostgreSQL

require("dotenv").config();
const { Pool } = require("pg");

// Connection string (local .env or Heroku)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("amazonaws") ? { rejectUnauthorized: false } : false
});

// Shortcut query function
const q = (text, params = []) => pool.query(text, params);

// Log connection
pool.connect()
  .then(() => console.log("PostgreSQL connected OK"))
  .catch(err => console.error("PostgreSQL connection error:", err));


// =======================================================
// TABLE INITIALIZATION
// =======================================================

(async () => {
  try {
    // USERS
    await q(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan_id INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP,
        reset_token TEXT,
        reset_expire BIGINT
      );
    `);

    // PLANS
    await q(`
      CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        quota INTEGER NOT NULL
      );
    `);

    // Insert default plans
    await q(`INSERT INTO plans (id,name,quota) VALUES (1,'FREE',15)
             ON CONFLICT (id) DO NOTHING`);
    await q(`INSERT INTO plans (id,name,quota) VALUES (2,'BASIC',50)
             ON CONFLICT (id) DO NOTHING`);
    await q(`INSERT INTO plans (id,name,quota) VALUES (3,'PRO',100)
             ON CONFLICT (id) DO NOTHING`);
    await q(`INSERT INTO plans (id,name,quota) VALUES (4,'ENTERPRISE',250)
             ON CONFLICT (id) DO NOTHING`);

    // HISTORY
    await q(`
      CREATE TABLE IF NOT EXISTS history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        timestamp BIGINT NOT NULL,
        query TEXT,
        type TEXT,
        result TEXT
      );
    `);

    // QUOTA USAGE
    await q(`
      CREATE TABLE IF NOT EXISTS quota_usage (
        user_id INTEGER PRIMARY KEY,
        used INTEGER DEFAULT 0
      );
    `);

    // PASSWORD RESET TABLE (optional)
    await q(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("PostgreSQL schema ready.");
  } catch (err) {
    console.error("Schema initialization error:", err);
  }
})();


// =======================================================
// USER FUNCTIONS
// =======================================================

module.exports.createUser = async (name, email, hash, cb) => {
  try {
    const res = await q(
      `INSERT INTO users (name,email,password_hash) VALUES ($1,$2,$3) RETURNING id`,
      [name, email, hash]
    );
    cb && cb(null, res.rows[0].id);
  } catch (err) {
    cb && cb(err);
  }
};

module.exports.getUserByEmail = (email, cb) => {
  q(`SELECT * FROM users WHERE email = $1`, [email])
    .then(r => cb(null, r.rows[0] || null))
    .catch(err => cb(err));
};

module.exports.getUserById = (id, cb) => {
  q(`SELECT * FROM users WHERE id = $1`, [id])
    .then(r => cb(null, r.rows[0] || null))
    .catch(err => cb(err));
};

module.exports.updateLastLogin = (id) => {
  q(`UPDATE users SET last_login = NOW() WHERE id = $1`, [id]);
};

module.exports.updateUserName = (id, name, cb) => {
  q(`UPDATE users SET name = $1 WHERE id = $2`, [name, id])
    .then(() => cb && cb(null))
    .catch(cb);
};

module.exports.updateUserPassword = (id, hash, cb) => {
  q(`UPDATE users SET password_hash = $1 WHERE id = $2`, [hash, id])
    .then(() => cb && cb(null))
    .catch(cb);
};


// =======================================================
// PASSWORD RESET HELPERS
// =======================================================

module.exports.setResetToken = (email, token, expire, cb) => {
  q(`UPDATE users SET reset_token = $1, reset_expire = $2 WHERE email = $3`,
    [token, expire, email])
    .then(() => cb && cb(null))
    .catch(cb);
};

module.exports.getUserByResetToken = (token, cb) => {
  const now = Date.now();

  // first try users.reset_token
  q(`SELECT * FROM users WHERE reset_token = $1 AND reset_expire > $2`,
    [token, now])
    .then(r => {
      if (r.rows.length) return cb(null, r.rows[0]);

      // otherwise check password_resets
      q(
        `SELECT user_id FROM password_resets WHERE token=$1 AND expires_at > NOW()`,
        [token]
      )
        .then(r2 => {
          if (!r2.rows.length) return cb(null, null);

          const uid = r2.rows[0].user_id;
          return q(`SELECT * FROM users WHERE id=$1`, [uid])
            .then(r3 => cb(null, r3.rows[0] || null))
            .catch(cb);
        })
        .catch(cb);
    })
    .catch(cb);
};

module.exports.clearResetToken = (id, cb) => {
  q(`UPDATE users SET reset_token=NULL, reset_expire=NULL WHERE id=$1`, [id])
    .then(() => cb && cb(null))
    .catch(cb);
};


// =======================================================
// PLANS
// =======================================================

module.exports.getPlans = (cb) => {
  q(`SELECT * FROM plans ORDER BY id ASC`)
    .then(r => cb(null, r.rows))
    .catch(cb);
};

module.exports.getPlanById = (id, cb) => {
  q(`SELECT * FROM plans WHERE id = $1`, [id])
    .then(r => cb(null, r.rows[0] || null))
    .catch(cb);
};

module.exports.setUserPlan = (user_id, plan_id, cb) => {
  q(`UPDATE users SET plan_id = $1 WHERE id = $2`, [plan_id, user_id])
    .then(() => cb && cb(null))
    .catch(cb);
};


// =======================================================
// QUOTA
// =======================================================

module.exports.getQuota = (user_id, cb) => {
  q(`SELECT used FROM quota_usage WHERE user_id = $1`, [user_id])
    .then(r => {
      const used = r.rows.length ? r.rows[0].used : 0;
      cb(null, used);
    })
    .catch(cb);
};

module.exports.incrementQuota = (user_id, cb) => {
  q(
    `INSERT INTO quota_usage (user_id, used)
     VALUES ($1, 1)
     ON CONFLICT (user_id)
     DO UPDATE SET used = quota_usage.used + 1`,
    [user_id]
  )
    .then(() => cb && cb(null))
    .catch(cb);
};

module.exports.resetQuota = (user_id, cb) => {
  q(`UPDATE quota_usage SET used = 0 WHERE user_id = $1`, [user_id])
    .then(() => cb && cb(null))
    .catch(cb);
};


// =======================================================
// HISTORY
// =======================================================

module.exports.addHistory = (user_id, query, type, result, cb) => {
  const ts = Date.now();
  q(
    `INSERT INTO history (user_id, timestamp, query, type, result)
     VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [user_id, ts, query, type, result]
  )
    .then(r => cb && cb(null, r.rows[0].id))
    .catch(cb);
};

module.exports.getHistory = (user_id, cb) => {
  q(
    `SELECT * FROM history WHERE user_id=$1 ORDER BY timestamp DESC`,
    [user_id]
  )
    .then(r => cb(null, r.rows))
    .catch(cb);
};

module.exports.getHistoryItem = (user_id, id, cb) => {
  q(
    `SELECT * FROM history WHERE id=$1 AND user_id=$2`,
    [id, user_id]
  )
    .then(r => cb(null, r.rows[0] || null))
    .catch(cb);
};


// expose raw pool if needed
module.exports.pool = pool;

