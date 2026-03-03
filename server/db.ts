
import Database from 'better-sqlite3';

const db = new Database('aegis.db');

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Initial Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    status TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_session_id TEXT NOT NULL,
    url TEXT NOT NULL,
    waf_detected TEXT,
    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions(id)
  );

  CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    description TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    closed_at INTEGER,
    status TEXT DEFAULT 'open',
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
  );

  CREATE TABLE IF NOT EXISTS payload_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    payload TEXT NOT NULL,
    payload_type TEXT,
    waf_blocked BOOLEAN DEFAULT 0,
    response_status INTEGER,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
    FOREIGN KEY (target_id) REFERENCES targets(id)
  );

  CREATE TABLE IF NOT EXISTS oob_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_session_id TEXT NOT NULL,
    interaction_type TEXT NOT NULL, -- (e.g., DNS, HTTP)
    subdomain TEXT NOT NULL,
    ip_address TEXT,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions(id)
  );
`);

export default db;
