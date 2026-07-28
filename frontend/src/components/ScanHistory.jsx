const LEVEL_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)',
  LOW: 'var(--sev-low)',
}

export default function ScanHistory({ scans, onSelect }) {
  if (!scans.length) return null

  return (
    <div>
      <div className="section-header">
        <div className="section-title">Past scans</div>
      </div>
      <div className="history-list">
        {scans.map(s => (
          <div className="history-row" key={s.id} onClick={() => onSelect(s.id)}>
            <span className="history-target">{s.target_url}</span>
            <span className="history-meta">
              {s.pages_crawled ?? 0} pages
              {s.risk_level && (
                <span
                  className="level-tag"
                  style={{
                    color: LEVEL_COLORS[s.risk_level],
                    background: `${LEVEL_COLORS[s.risk_level]}22`,
                  }}
                >
                  {s.risk_level}
                </span>
              )}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
