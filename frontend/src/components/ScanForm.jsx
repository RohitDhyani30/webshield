import { useState } from 'react'

export default function ScanForm({ onSubmit, scanning }) {
  const [url, setUrl] = useState('')
  const [consent, setConsent] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [maxPages, setMaxPages] = useState('')
  const [maxDepth, setMaxDepth] = useState('')
  const [error, setError] = useState(null)

  function handleSubmit(e) {
    e.preventDefault()
    setError(null)

    if (!url.trim()) {
      setError('Enter a target URL to scan.')
      return
    }
    if (!consent) {
      setError('You must confirm you own or have permission to test this target.')
      return
    }

    onSubmit({
      targetUrl: url.trim(),
      consentConfirmed: consent,
      maxPages: maxPages ? parseInt(maxPages, 10) : undefined,
      maxDepth: maxDepth ? parseInt(maxDepth, 10) : undefined,
    }).catch(err => setError(err.message))
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <label className="field-label" htmlFor="target-url">Target URL</label>
      <input
        id="target-url"
        className="text-input"
        type="text"
        placeholder="http://testphp.vulnweb.com"
        value={url}
        onChange={e => setUrl(e.target.value)}
        disabled={scanning}
      />

      <button
        type="button"
        className="advanced-toggle"
        onClick={() => setShowAdvanced(v => !v)}
      >
        {showAdvanced ? 'Hide' : 'Show'} crawl limits
      </button>

      {showAdvanced && (
        <div className="advanced-grid">
          <div>
            <label className="field-label" htmlFor="max-pages">Max pages</label>
            <input
              id="max-pages"
              className="text-input"
              type="number"
              min="1"
              placeholder="50"
              value={maxPages}
              onChange={e => setMaxPages(e.target.value)}
              disabled={scanning}
            />
          </div>
          <div>
            <label className="field-label" htmlFor="max-depth">Max depth</label>
            <input
              id="max-depth"
              className="text-input"
              type="number"
              min="1"
              placeholder="3"
              value={maxDepth}
              onChange={e => setMaxDepth(e.target.value)}
              disabled={scanning}
            />
          </div>
        </div>
      )}

      <label className="consent-row">
        <input
          type="checkbox"
          checked={consent}
          onChange={e => setConsent(e.target.checked)}
          disabled={scanning}
        />
        <span>I own this target, or have written permission to test it. Scanning systems without authorization may be illegal.</span>
      </label>

      <div className="submit-row">
        <button type="submit" className="btn-primary" disabled={scanning}>
          {scanning ? 'Scanning…' : 'Run scan'}
        </button>
        {scanning && (
          <span className="status-line" style={{ marginTop: 0 }}>
            <span className="spinner" />
            crawling target, running detectors
          </span>
        )}
      </div>

      {error && <div className="error-banner">{error}</div>}
    </form>
  )
}
