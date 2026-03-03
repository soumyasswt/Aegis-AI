import express from 'express';
import db from './db';

const router = express.Router();

// Aggregated heatmap: severity vs confidence with WAF evasion
router.get('/heatmap/severity-confidence-waf', (req, res) => {
  const rows = db.prepare(`
    SELECT
      v.severity,
      v.confidence,
      SUM(CASE WHEN p.waf_blocked = 1 THEN 1 ELSE 0 END) AS blocked,
      SUM(CASE WHEN p.waf_blocked = 0 THEN 1 ELSE 0 END) AS passed
    FROM vulnerabilities v
    JOIN payload_attempts p ON v.id = p.vulnerability_id
    GROUP BY v.severity, v.confidence
    ORDER BY
      CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 END,
      CASE v.confidence WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 END
  `).all();

  const heatmap: Record<string, Record<string, { blocked: number, passed: number }>> = {};

  rows.forEach((r: any) => {
    if (!heatmap[r.severity]) {
      heatmap[r.severity] = {};
    }
    heatmap[r.severity][r.confidence] = { blocked: r.blocked, passed: r.passed };
  });

  res.json(heatmap);
});

export default router;
