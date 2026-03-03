import { crawlWebsite } from './crawler.js';
import { runScanner } from './scanner.js';
import { runFuzzer } from './fuzzer.js';
import { analyzeEndpoints } from './llm.js';
import db from './db.js';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

// In-memory store for scan sessions (will be replaced by DB later)
export const scanSessions = new Map<string, any>();

function generateFingerprint(url: string, type: string, poc: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(`${url}|${type}|${poc}`);
  return hash.digest('hex');
}

export async function scanPipeline(url: string, sessionId: string) {
  const session = scanSessions.get(sessionId);
  if (!session) return;

  const appUrl = process.env.APP_URL || 'http://localhost:3000';

  // Ensure target exists
  let targetId = uuidv4();
  const existingTarget = db.prepare('SELECT id FROM targets WHERE url = ?').get(url) as any;
  if (existingTarget) {
    targetId = existingTarget.id;
    db.prepare('UPDATE targets SET last_scan_at = CURRENT_TIMESTAMP WHERE id = ?').run(targetId);
  } else {
    db.prepare('INSERT INTO targets (id, url, last_scan_at) VALUES (?, ?, CURRENT_TIMESTAMP)').run(targetId, url);
  }

  // Create scan record
  db.prepare('INSERT INTO scans (id, target_id, status) VALUES (?, ?, ?)').run(sessionId, targetId, 'Running');

  try {
    session.status = 'Crawling...';
    const endpoints = await crawlWebsite(url);
    session.endpoints = endpoints;

    // Save endpoints to DB
    const insertEndpoint = db.prepare('INSERT OR IGNORE INTO endpoints (id, target_id, path, method) VALUES (?, ?, ?, ?)');
    const insertParam = db.prepare('INSERT OR IGNORE INTO parameters (id, endpoint_id, name, type) VALUES (?, ?, ?, ?)');
    
    for (const ep of endpoints) {
      const epId = uuidv4();
      const parsedUrl = new URL(ep.url);
      insertEndpoint.run(epId, targetId, parsedUrl.pathname, ep.method);
      
      for (const param of ep.params) {
        insertParam.run(uuidv4(), epId, param, 'GET');
      }
    }

    session.status = 'Running Traditional Scanners...';
    const scanResults = await runScanner(endpoints, sessionId, appUrl, targetId);

    session.status = 'Fuzzing Endpoints (Active Verification)...';
    const fuzzResults = await runFuzzer(endpoints);

    session.status = 'LLM Analysis (Augmentation)...';
    const verifiedVulns = [...scanResults, ...fuzzResults];
    const llmResults = await analyzeEndpoints(endpoints, verifiedVulns);

    // Merge results
    const allVulnerabilities = [...verifiedVulns, ...llmResults];
    
    // Deduplicate by URL and Type locally first
    const uniqueVulns = Array.from(new Map(allVulnerabilities.map(item => [`${item.url}-${item.type}`, item])).values());

    // Save vulnerabilities to DB with fingerprinting
    const checkVuln = db.prepare(`SELECT id, status FROM vulnerabilities WHERE fingerprint = ? AND target_id = ?`);
    const updateVuln = db.prepare(`UPDATE vulnerabilities SET last_seen_at = CURRENT_TIMESTAMP, status = 'open', closed_at = NULL WHERE id = ?`);
    const insertVuln = db.prepare(`
      INSERT INTO vulnerabilities (id, scan_id, target_id, type, severity, confidence, proof_of_concept, explanation, mitigation, fingerprint, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
    `);
    
    for (const vuln of uniqueVulns) {
      const poc = vuln.proofOfConcept || vuln.poc || vuln.url;
      const fingerprint = generateFingerprint(vuln.url, vuln.type, poc);
      
      const existing = checkVuln.get(fingerprint, targetId) as { id: string, status: string } | undefined;
      
      if (existing) {
        // Update last seen and reopen if it was closed
        updateVuln.run(existing.id);
      } else {
        // Insert new vulnerability
        insertVuln.run(
          uuidv4(),
          sessionId,
          targetId,
          vuln.type,
          vuln.severity,
          vuln.confidence,
          poc,
          vuln.explanation || '',
          vuln.mitigation || '',
          fingerprint
        );
      }
    }

    session.status = 'Completed';
    session.vulnerabilities = uniqueVulns;
    db.prepare('UPDATE scans SET status = ?, end_time = CURRENT_TIMESTAMP WHERE id = ?').run('Completed', sessionId);
  } catch (error: any) {
    console.error('Pipeline error:', error);
    session.status = 'Failed';
    session.error = error.message;
    db.prepare('UPDATE scans SET status = ?, end_time = CURRENT_TIMESTAMP WHERE id = ?').run('Failed', sessionId);
  }
}
