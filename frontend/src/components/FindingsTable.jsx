import { useState, useMemo } from 'react'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function FindingsTable({ findings }) {
  const [activeFilter, setActiveFilter] = useState('ALL')

  const sorted = useMemo(() => {
    return [...findings].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    )
  }, [findings])

  const filtered = activeFilter === 'ALL'
    ? sorted
    : sorted.filter(f => f.severity === activeFilter)

  return (
    <div>
      <div className="section-header">
        <div className="section-title">Findings ({findings.length})</div>
      </div>

      <div className="filter-chips">
        <button
          className={`chip ${activeFilter === 'ALL' ? 'active' : ''}`}
          onClick={() => setActiveFilter('ALL')}
        >
          all
        </button>
        {SEVERITY_ORDER.map(sev => (
          <button
            key={sev}
            className={`chip ${activeFilter === sev ? 'active' : ''}`}
            onClick={() => setActiveFilter(sev)}
          >
            {sev.toLowerCase()}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">
          {findings.length === 0
            ? 'no findings — target looks clean for the checks run'
            : 'nothing matches this filter'}
        </div>
      ) : (
        <div className="finding-list">
          {filtered.map((f, i) => (
            <div className="finding-row" key={i}>
              <span className={`sev-tag sev-${f.severity}`}>{f.severity}</span>
              <div>
                <div className="finding-title">{f.title}</div>
                <div className="finding-meta">
                  {f.module}
                  {f.url ? ` · ${f.url}` : ''}
                  {f.parameter ? ` · param: ${f.parameter}` : ''}
                </div>
                {f.remediation && (
                  <div className="finding-remediation">{f.remediation}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
