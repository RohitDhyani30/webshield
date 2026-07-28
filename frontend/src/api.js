// Thin wrapper around the WebShield backend API.
// Dev server proxies /api/* to http://localhost:8000 (see vite.config.js).

const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const message = body.detail
      ? (Array.isArray(body.detail) ? body.detail.map(d => d.msg).join(', ') : body.detail)
      : `Request failed (${res.status})`
    throw new Error(message)
  }
  return res.json()
}

export function startScan({ targetUrl, consentConfirmed, maxPages, maxDepth }) {
  return request('/scans', {
    method: 'POST',
    body: JSON.stringify({
      target_url: targetUrl,
      consent_confirmed: consentConfirmed,
      max_pages: maxPages || null,
      max_depth: maxDepth || null,
    }),
  })
}

export function getScan(scanId) {
  return request(`/scans/${scanId}`)
}

export function listScans() {
  return request('/scans')
}

export function reportUrl(scanId, format) {
  return `${BASE}/scans/${scanId}/report/${format}`
}
