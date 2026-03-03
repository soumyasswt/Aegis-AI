import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const dbPath = path.join(process.cwd(), 'aegis.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    last_scan_at DATETIME,
    waf_detected BOOLEAN DEFAULT 0,
    waf_name TEXT,
    notes TEXT
  );

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    status TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
  );

  CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
  );

  CREATE TABLE IF NOT EXISTS parameters (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
  );

  CREATE TABLE IF NOT EXISTS payload_attempts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    parameter_id TEXT,
    payload TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    response_signature TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id),
    FOREIGN KEY(parameter_id) REFERENCES parameters(id)
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    endpoint_id TEXT,
    parameter_id TEXT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME,
    status TEXT DEFAULT 'open',
    fingerprint TEXT UNIQUE,
    proof_of_concept TEXT,
    explanation TEXT,
    mitigation TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id),
    FOREIGN KEY(target_id) REFERENCES targets(id),
    FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
    FOREIGN KEY(parameter_id) REFERENCES parameters(id)
  );

  CREATE TABLE IF NOT EXISTS oob_payloads (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    parameter TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    hit_at DATETIME,
    source_ip TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
  );
`);

try {
  db.exec('ALTER TABLE vulnerabilities ADD COLUMN closed_at DATETIME;');
} catch (e) {
  // Ignore if column already exists
}

export default db;
