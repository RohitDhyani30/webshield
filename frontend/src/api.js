// Thin wrapper around the WebShield backend API.
// Local dev: Vite proxies /api/* to http://localhost:8000 (see vite.config.js), so BASE stays '/api'.
// Production (Vercel): set VITE_API_BASE_URL to Render backend URL, e.g.
//   https://webshield-backend.onrender.com/api


const BASE = import.meta.env.VITE_API_BASE_URL || '/api'

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
