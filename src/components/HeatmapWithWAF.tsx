import React, { useEffect, useState } from 'react';

interface CellData {
  blocked: number;
  passed: number;
}

type HeatmapData = Record<string, Record<string, CellData>>;

export const HeatmapWithWAF = () => {
  const [data, setData] = useState<HeatmapData>({});

  useEffect(() => {
    fetch('/api/analytics/heatmap/severity-confidence-waf')
      .then(res => res.json())
      .then(setData);
  }, []);

  const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
  const confidenceOrder = ['High', 'Medium', 'Low'];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-2xl font-bold font-display text-[var(--color-peacock-blue)] mb-1">
          WAF Evasion Heatmap
        </h3>
        <p className="text-md text-[var(--color-charcoal)]/70">
          Severity vs. Confidence, correlated with WAF block/pass status.
        </p>
      </div>

      <div className="grid grid-cols-[auto_1fr_1fr_1fr] gap-x-6 gap-y-4 items-center">
        {/* Header row: Confidence */}
        <div></div> {/* Empty corner */}
        {confidenceOrder.map(conf => (
          <div key={conf} className="text-center font-display font-bold text-xl text-[var(--color-peacock-blue)] pb-2">{conf}</div>
        ))}

        {/* Data rows: Severity */}
        {severityOrder.map(sev => (
          <React.Fragment key={sev}>
            <div className="font-display font-bold text-xl text-right text-[var(--color-peacock-blue)] pr-6">{sev}</div>
            {confidenceOrder.map(conf => {
              const cell = data[sev]?.[conf] || { blocked: 0, passed: 0 };
              const total = cell.blocked + cell.passed;
              const passedPct = total > 0 ? (cell.passed / total) * 100 : 0;
              const blockedPct = total > 0 ? (cell.blocked / total) * 100 : 0;
              const intensity = Math.min(total / 20, 1); // Increased denominator for more subtle effect

              return (
                <div
                  key={conf}
                  className="border-2 rounded-2xl p-4 h-40 flex flex-col justify-between shadow-inner transition-all duration-300"
                  style={{
                    backgroundColor: total > 0 ? `rgba(217, 3, 104, ${0.05 + intensity * 0.15})` : 'var(--color-sand)',
                    borderColor: total > 0 ? `rgba(0, 95, 115, ${0.1 + intensity * 0.25})` : 'rgba(0, 95, 115, 0.1)',
                  }}
                >
                  <div className="text-center">
                    <div className="text-5xl font-display font-bold text-[var(--color-peacock-blue)]">
                      {total}
                    </div>
                    <div className="text-sm text-[var(--color-charcoal)]/60 font-semibold -mt-1">
                      {total === 1 ? 'finding' : 'findings'}
                    </div>
                  </div>
                  <div className="space-y-1.5 pt-2">
                    <div
                      className="w-full h-4 flex rounded-full overflow-hidden bg-sand/80 border-2 border-white/50 shadow-sm"
                      title={`Blocked: ${cell.blocked} (${blockedPct.toFixed(0)}%), Passed: ${cell.passed} (${passedPct.toFixed(0)}%)`}
                    >
                      <div
                        className="h-full transition-all duration-500"
                        style={{ width: `${blockedPct}%`, backgroundColor: 'var(--color-jade-green)' }}
                      ></div>
                      <div
                        className="h-full transition-all duration-500"
                        style={{ width: `${passedPct}%`, backgroundColor: 'var(--color-terracotta)' }}
                      ></div>
                    </div>
                    <div className="text-xs text-[var(--color-charcoal)]/90 flex justify-between px-1">
                      <span className="font-bold" style={{color: 'var(--color-jade-green)'}}>Blocked: {cell.blocked}</span>
                      <span className="font-bold" style={{color: 'var(--color-terracotta)'}}>Passed: {cell.passed}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
