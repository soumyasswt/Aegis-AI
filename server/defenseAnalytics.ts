import express from 'express';
import db from './db';

const router = express.Router();

// WAF Evasion Analytics
router.get('/waf-evasion', (req, res) => {
  const rows = db.prepare(`
    SELECT
      p.payload_type,
      t.url AS target,
      SUM(CASE WHEN p.waf_blocked = 1 THEN 1 ELSE 0 END) AS blocked,
      SUM(CASE WHEN p.waf_blocked = 0 THEN 1 ELSE 0 END) AS passed
    FROM payload_attempts p
    JOIN targets t ON p.target_id = t.id
    GROUP BY t.url, p.payload_type
    ORDER BY blocked DESC
  `).all();

  // Format for frontend grid: { target: { payload_type: { blocked, passed } } }
  const result: Record<string, Record<string, { blocked: number, passed: number }>> = {};

  rows.forEach((r: any) => {
    if (!result[r.target]) {
      result[r.target] = {};
    }
    result[r.target][r.payload_type] = { blocked: r.blocked, passed: r.passed };
  });

  res.json(result);
});

export default router;
