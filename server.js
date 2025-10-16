// server.js (hardened)
// Required packages: express body-parser sqlite3 express-validator jsonwebtoken cookie-parser dotenv helmet
// Install: npm i express body-parser sqlite3 express-validator jsonwebtoken cookie-parser dotenv helmet

require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 1234;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'users.db');

// ---- sanity check for required secrets ----
if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.error("Missing secrets in .env — copy .env.example -> .env and set secrets");
  process.exit(1);
}
const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ISS = process.env.TOKEN_ISSUER || 'example.auth';
const AUD = process.env.TOKEN_AUDIENCE || 'example.api';
const ACCESS_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || '10m';
const REFRESH_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES || '7d';
const NODE_ENV = process.env.NODE_ENV || 'development';

// ---- middleware ----
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- open DB & initialize tables if not exists ----
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) return console.error("DB open error:", err);
  console.log("🗄️  Connected to SQLite DB at", DB_PATH);
});

// Promisified helpers for sqlite3 (simple wrappers)
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// Create required tables if they don't exist
async function initDb() {
  // users table (if assignment repo doesn't include it)
  await dbRun(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );`);
  // refresh_tokens table for rotation
  await dbRun(`CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );`);
  console.log("✅ DB ensured tables: users, refresh_tokens");
}
initDb().catch(err => {
  console.error("DB init error:", err);
  process.exit(1);
});

// ---- token helpers ----
function generateJwtId() {
  return crypto.randomBytes(16).toString('hex'); // 32 hex chars
}

function signAccessToken(userId, extra = {}) {
  return jwt.sign(
    { sub: String(userId), ...extra },
    ACCESS_SECRET,
    {
      expiresIn: ACCESS_EXPIRES,
      issuer: ISS,
      audience: AUD,
      algorithm: 'HS256',
      jwtid: generateJwtId(),
    }
  );
}

function signRefreshToken(userId) {
  return jwt.sign(
    { sub: String(userId) },
    REFRESH_SECRET,
    {
      expiresIn: REFRESH_EXPIRES,
      issuer: ISS,
      audience: AUD,
      algorithm: 'HS256',
      jwtid: generateJwtId(),
    }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_SECRET, {
    algorithms: ['HS256'],
    issuer: ISS,
    audience: AUD
  });
}

function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET, {
    algorithms: ['HS256'],
    issuer: ISS,
    audience: AUD
  });
}

// ---- helpers: store / revoke refresh tokens ----
async function storeRefreshToken(jti, userId, expiresAtEpoch) {
  await dbRun(`INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)`, [jti, String(userId), expiresAtEpoch]);
}
async function revokeRefreshToken(jti) {
  await dbRun(`UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?`, [jti]);
}
async function isRefreshTokenValid(jti) {
  const row = await dbGet(`SELECT * FROM refresh_tokens WHERE jti = ?`, [jti]);
  if (!row) return false;
  if (row.revoked) return false;
  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at <= now) return false;
  return true;
}

// ---- routes ----

// Serve index or static (same as original)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Documentation endpoint
app.get('/register', (req, res) => {
  res.json({
    api: "SQL Injection Lab API (Hardened version)",
    description: "POST /vuln-login demonstrates vulnerable SQL concatenation. POST /login demonstrates safe parameterized queries. /refresh uses refresh-token rotation and HttpOnly cookie.",
    endpoints: {
      "POST /vuln-login": { "body": { "username": "string", "password": "string" }, "notes": "VULNERABLE — for demo only" },
      "POST /login": { "body": { "username":"string", "password":"string" }, "notes": "SECURE — uses parameterized queries and issues tokens" },
      "POST /refresh": { "notes": "Set-Cookie: refreshToken=... HttpOnly" },
      "POST /logout": { "notes": "Revoke refresh token (cookie or body)" }
    }
  });
});

/*
  VULNERABLE LOGIN (for demonstration) - left intact for assignment comparison
*/
app.post('/vuln-login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
  console.log("🔴 [VULN] Constructed SQL:", sql);

  dbAll(sql, []).then(rows => {
    if (rows && rows.length > 0) {
      return res.json({ success: true, message: `VULN login success for user: ${rows[0].username}`, rows });
    } else {
      return res.status(401).json({ success: false, message: "VULN login failed" });
    }
  }).catch(err => {
    console.error("[VULN] SQL error:", err);
    return res.status(500).json({ error: "DB error (vuln)" });
  });
});

/*
  SECURE LOGIN — uses parameterized query.
  On success: issue access token (in JSON) and refresh token (HttpOnly cookie).
*/
app.post(
  '/login',
  body('username').trim().isLength({ min: 1 }).escape(),
  body('password').trim().isLength({ min: 1 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const { username, password } = req.body;
      const sql = "SELECT * FROM users WHERE username = ? AND password = ?;";
      console.log("🟢 [SECURE] Executing parameterized SQL:", sql, "with params:", [username, password]);

      const row = await dbGet(sql, [username, password]);
      if (!row) {
        return res.status(401).json({ success: false, message: "SECURE login failed" });
      }

      // Create tokens
      const accessToken = signAccessToken(row.id);
      const refreshToken = signRefreshToken(row.id);

      // decode to retrieve jti and exp
      const decoded = jwt.decode(refreshToken, { complete: true });
      const jti = decoded && decoded.payload && decoded.payload.jti ? decoded.payload.jti : decoded && decoded.header && decoded.header.jti;
      const exp = decoded && decoded.payload && decoded.payload.exp ? decoded.payload.exp : null;

      // store refresh token jti server-side
      if (jti && exp) {
        await storeRefreshToken(jti, row.id, exp);
      } else {
        console.warn("Could not decode jti/exp for refresh token; not storing refresh token server-side");
      }

      // Set refresh token as HttpOnly cookie
      const cookieOptions = {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7 // max 7 days: client-side expiry (ms)
      };
      res.cookie('refreshToken', refreshToken, cookieOptions);

      console.log(`🔐 Issued tokens for user ${row.username} (id=${row.id})`);
      return res.json({ success: true, accessToken });
    } catch (err) {
      next(err);
    }
  }
);

// Protected example route (uses Authorization: Bearer <accessToken>)
app.get('/protected', async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No access token provided' });
    }
    const token = auth.split(' ')[1];
    const payload = verifyAccessToken(token); // will throw if invalid/expired
    return res.json({ ok: true, sub: payload.sub, iat: payload.iat, exp: payload.exp });
  } catch (err) {
    console.error("Protected route error:", err.name, err.message);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'TokenExpired', details: err.message });
    }
    return res.status(401).json({ error: 'InvalidToken', details: err.message });
  }
});

/*
  POST /refresh
  - Reads refresh token from HttpOnly cookie OR from JSON body (for testing).
  - Verifies token (signature + iss + aud + alg)
  - Checks server-side store for jti and revoked/expires
  - If valid: revoke old jti, issue new refresh token (rotation) and new access token
*/
app.post('/refresh', async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (!token) return res.status(401).json({ error: 'No refresh token provided' });

    let decoded;
    try {
      decoded = verifyRefreshToken(token);
    } catch (err) {
      console.error("Refresh token verification failed:", err.name, err.message);
      return res.status(401).json({ error: 'Invalid or expired refresh token', details: err.message });
    }

    const jti = jwt.decode(token).jti;
    if (!jti) return res.status(401).json({ error: 'Invalid refresh token (no jti)' });

    const valid = await isRefreshTokenValid(jti);
    if (!valid) {
      // Potential replay or revoked token
      console.warn("Refresh token invalid or revoked:", jti);
      return res.status(401).json({ error: 'Refresh token revoked or expired' });
    }

    // Revoke current refresh jti (single-use)
    await revokeRefreshToken(jti);

    // Issue new tokens
    const newAccess = signAccessToken(decoded.sub);
    const newRefresh = signRefreshToken(decoded.sub);
    const newDecoded = jwt.decode(newRefresh);
    const newJti = newDecoded.jti;
    const newExp = newDecoded.exp;
    if (newJti && newExp) {
      await storeRefreshToken(newJti, decoded.sub, newExp);
    }

    // set new refresh cookie
    const cookieOptions = {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7
    };
    res.cookie('refreshToken', newRefresh, cookieOptions);

    console.log(`🔁 Rotated refresh token for user ${decoded.sub}`);
    return res.json({ accessToken: newAccess });
  } catch (err) {
    console.error("Refresh endpoint error:", err);
    return res.status(500).json({ error: 'Server error on refresh' });
  }
});

// POST /logout - revoke the refresh token (from cookie or body)
app.post('/logout', async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (!token) {
      // nothing to revoke
      res.clearCookie('refreshToken');
      return res.json({ ok: true, message: 'Logged out (no token present)' });
    }
    const decoded = jwt.decode(token);
    const jti = decoded && decoded.jti;
    if (jti) {
      await revokeRefreshToken(jti);
    }
    res.clearCookie('refreshToken');
    return res.json({ ok: true, message: 'Logged out' });
  } catch (err) {
    console.error("Logout error:", err);
    return res.status(500).json({ error: 'Server error on logout' });
  }
});

// Optional: admin list users (protected example)
// For demo/teacher only — in production restrict this
app.get('/admin/list-users', async (req, res) => {
  try {
    const rows = await dbAll("SELECT id, username FROM users", []);
    res.json({ users: rows });
  } catch (err) {
    console.error("List users error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

// ---- centralized error handler ----
app.use((err, req, res, next) => {
  console.error("Server Error:", err && err.stack ? err.stack : err);
  if (err && err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'TokenExpired', details: err.message });
  }
  if (err && err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'InvalidToken', details: err.message });
  }
  if (err && err.code && err.code.startsWith && err.code.startsWith('SQLITE_')) {
    return res.status(500).json({ error: 'DatabaseError', details: err.message });
  }
  res.status(500).json({ error: 'ServerError', details: err && err.message ? err.message : 'unknown' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`🔐 Issuer=${ISS} Audience=${AUD} AccessExpiry=${ACCESS_EXPIRES} RefreshExpiry=${REFRESH_EXPIRES}`);
});
