// init-db.js
// -----------------------------
// Initializes SQLite database for the lab
// Creates 'users' and 'refresh_tokens' tables
// Inserts demo users
// -----------------------------

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Database file path (same as in server.js)
const DB_PATH = path.join(__dirname, 'users.db');

// Open database connection
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("❌ Cannot open DB:", err.message);
    process.exit(1);
  }
  console.log("🗄️  Connected to SQLite DB at", DB_PATH);
});

// SQL statements
const initSQL = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  jti TEXT UNIQUE NOT NULL,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

INSERT OR IGNORE INTO users (username, password)
VALUES
  ('alice', 'secret123'),
  ('bob', 'pass123'),
  ('charlie', 'letmein');
`;

db.exec(initSQL, (err) => {
  if (err) {
    console.error("❌ Error initializing DB:", err.message);
  } else {
    console.log("✅ Database initialized successfully.");
  }
  db.close();
});
