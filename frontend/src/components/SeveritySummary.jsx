// Derives severity counts directly from the findings list — keeps the UI in
// sync with whatever the backend actually returned, rather than trusting a
// separately-computed count that could drift.
function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1
  }
  return counts
}

export default function SeveritySummary({ scan }) {
  const counts = countBySeverity(scan.findings || [])

  return (
    <div className="summary">
      <div className="summary-cell score-cell">
        <div className="summary-value">{scan.risk_score ?? '—'}</div>
        <div className="summary-label">Risk score</div>
      </div>
      <div className="summary-cell">
        <div className="summary-value" style={{ color: 'var(--sev-critical)' }}>{counts.CRITICAL}</div>
        <div className="summary-label">Critical</div>
      </div>
      <div className="summary-cell">
        <div className="summary-value" style={{ color: 'var(--sev-high)' }}>{counts.HIGH}</div>
        <div className="summary-label">High</div>
      </div>
      <div className="summary-cell">
        <div className="summary-value" style={{ color: 'var(--sev-medium)' }}>{counts.MEDIUM}</div>
        <div className="summary-label">Medium</div>
      </div>
      <div className="summary-cell">
        <div className="summary-value" style={{ color: 'var(--sev-low)' }}>{counts.LOW}</div>
        <div className="summary-label">Low</div>
      </div>
    </div>
  )
}
