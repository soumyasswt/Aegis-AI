import express from 'express';
import { createServer as createViteServer } from 'vite';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import { scanSessions, scanPipeline } from './server/orchestrator.js';
import { handleOobCallback } from './server/oobFuzzer.js';
import db from './server/db.js';
import defenseAnalyticsRouter from './server/defenseAnalytics.js';
import defenseHeatmapRouter from './server/defenseHeatmap.js';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// --- API Routes ---

app.use('/api/analytics', defenseAnalyticsRouter);
app.use('/api/analytics', defenseHeatmapRouter);

app.get('/api/oob/:id', (req, res) => {
  const { id } = req.params;
  handleOobCallback(id, {
    ip: req.ip,
    headers: req.headers,
    query: req.query,
    timestamp: new Date().toISOString()
  });
  res.status(200).send('OK');
});

app.post('/api/scan', (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  const sessionId = uuidv4();
  scanSessions.set(sessionId, {
    id: sessionId,
    url,
    status: 'Initializing...',
    endpoints: [],
    vulnerabilities: [],
    startTime: new Date().toISOString()
  });

  // Start pipeline in background
  scanPipeline(url, sessionId);

  res.json({ sessionId, status: 'Scan started' });
});

app.get('/api/scan/:id', (req, res) => {
  const session = scanSessions.get(req.params.id);
  if (!session) {
    return res.status(404).json({ error: 'Scan session not found' });
  }
  res.json(session);
});

// --- Database API Routes ---

app.get('/api/targets', (req, res) => {
  try {
    const targets = db.prepare('SELECT * FROM targets ORDER BY last_scan_at DESC').all();
    res.json(targets);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/targets/:id/scans', (req, res) => {
  try {
    const scans = db.prepare('SELECT * FROM scans WHERE target_id = ? ORDER BY start_time DESC').all(req.params.id);
    res.json(scans);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/scans/:id/vulnerabilities', (req, res) => {
  try {
    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    res.json(vulns);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/vulnerabilities', (req, res) => {
  try {
    const vulns = db.prepare(`
      SELECT v.*, t.url as target_url 
      FROM vulnerabilities v
      JOIN targets t ON v.target_id = t.id
      ORDER BY v.last_seen_at DESC
    `).all();
    res.json(vulns);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/vulnerabilities/:id/status', (req, res) => {
  try {
    const { status } = req.body;
    if (status !== 'open' && status !== 'closed') {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const closedAt = status === 'closed' ? new Date().toISOString() : null;
    
    db.prepare(`
      UPDATE vulnerabilities 
      SET status = ?, closed_at = ?
      WHERE id = ?
    `).run(status, closedAt, req.params.id);
    
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/time-to-fix', (req, res) => {
  try {
    // Calculate average time to fix (in days) per severity
    const stats = db.prepare(`
      SELECT 
        severity, 
        AVG(julianday(closed_at) - julianday(discovered_at)) as avg_days_to_fix,
        COUNT(*) as count
      FROM vulnerabilities
      WHERE status = 'closed' AND closed_at IS NOT NULL
      GROUP BY severity
    `).all();
    res.json(stats);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/trends', (req, res) => {
  try {
    // Get new vs resolved vulnerabilities over time (by month)
    const newVulns = db.prepare(`
      SELECT strftime('%Y-%m', discovered_at) as month, COUNT(*) as count
      FROM vulnerabilities
      GROUP BY month
      ORDER BY month
    `).all();
    
    const resolvedVulns = db.prepare(`
      SELECT strftime('%Y-%m', closed_at) as month, COUNT(*) as count
      FROM vulnerabilities
      WHERE status = 'closed' AND closed_at IS NOT NULL
      GROUP BY month
      ORDER BY month
    `).all();
    
    res.json({ new: newVulns, resolved: resolvedVulns });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/heatmap/severity-confidence', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT severity, confidence, COUNT(*) AS count
      FROM vulnerabilities
      GROUP BY severity, confidence
      ORDER BY
        CASE severity
          WHEN 'Critical' THEN 1
          WHEN 'High' THEN 2
          WHEN 'Medium' THEN 3
          WHEN 'Low' THEN 4
        END,
        CASE confidence
          WHEN 'High' THEN 1
          WHEN 'Medium' THEN 2
          WHEN 'Low' THEN 3
        END;
    `).all() as { severity: string, confidence: string, count: number }[];

    const result: Record<string, Record<string, number>> = {};
    rows.forEach(r => {
      if (!result[r.severity]) result[r.severity] = {};
      result[r.severity][r.confidence] = r.count;
    });

    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/heatmap/target-type', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT t.url AS target, v.type AS vuln_type, COUNT(*) AS count
      FROM vulnerabilities v
      JOIN targets t ON v.target_id = t.id
      GROUP BY t.url, v.type
      ORDER BY count DESC;
    `).all() as { target: string, vuln_type: string, count: number }[];

    const result: Record<string, Record<string, number>> = {};
    rows.forEach(r => {
      if (!result[r.target]) result[r.target] = {};
      result[r.target][r.vuln_type] = r.count;
    });

    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/oob-hits', (req, res) => {
  try {
    const hits = db.prepare('SELECT * FROM oob_payloads WHERE hit_at IS NOT NULL ORDER BY hit_at DESC').all();
    res.json(hits);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// --- Vite Middleware ---
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { 
        middlewareMode: true,
        hmr: false
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
