import { reportUrl } from '../api'

export default function ReportActions({ scanId }) {
  return (
    <div className="report-actions">
      <a className="btn-ghost" href={reportUrl(scanId, 'html')} target="_blank" rel="noreferrer">
        View HTML report
      </a>
      <a className="btn-ghost" href={reportUrl(scanId, 'pdf')}>
        Download PDF
      </a>
    </div>
  )
}
