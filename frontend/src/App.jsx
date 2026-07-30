import { useState, useEffect, useCallback } from 'react'
import Header from './components/Header'
import IntroPanel from './components/IntroPanel'
import ScanForm from './components/ScanForm'
import SeveritySummary from './components/SeveritySummary'
import FindingsTable from './components/FindingsTable'
import ReportActions from './components/ReportActions'
import ScanHistory from './components/ScanHistory'
import Footer from './components/Footer'
import { startScan, getScan, listScans } from './api'

export default function App() {
  const [scanning, setScanning] = useState(false)
  const [activeScan, setActiveScan] = useState(null)
  const [history, setHistory] = useState([])
  const [prefillUrl, setPrefillUrl] = useState('')

  const loadHistory = useCallback(() => {
    listScans().then(setHistory).catch(() => {})
  }, [])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  async function handleSubmit({ targetUrl, consentConfirmed, maxPages, maxDepth }) {
    setScanning(true)
    setActiveScan(null)
    try {
      const { scan_id } = await startScan({ targetUrl, consentConfirmed, maxPages, maxDepth })
      const result = await getScan(scan_id)
      setActiveScan(result)
      loadHistory()
    } finally {
      setScanning(false)
    }
  }

  async function handleSelectHistory(scanId) {
    const result = await getScan(scanId)
    setActiveScan(result)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <>
      <Header scanning={scanning} />

      <IntroPanel onPickExample={setPrefillUrl} />

      <ScanForm onSubmit={handleSubmit} scanning={scanning} prefillUrl={prefillUrl} />

      {activeScan && (
        <>
          <SeveritySummary scan={activeScan} />
          <ReportActions scanId={activeScan.scan_id} />
          <FindingsTable findings={activeScan.findings || []} />
        </>
      )}

      <div style={{ marginTop: 56 }}>
        <ScanHistory scans={history} onSelect={handleSelectHistory} />
      </div>

      <Footer />
    </>
  )
}
