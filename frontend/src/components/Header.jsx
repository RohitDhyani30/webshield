export default function Header({ scanning }) {
  return (
    <header className="header">
      <div className="header-row">
        <div className="brand">
          <span className={`brand-mark ${scanning ? 'active' : ''}`} />
          WebShield
        </div>
        <div className="tagline">non-exploitative DAST scanner</div>
      </div>
      <div className="sweep-track">
        {scanning && <div className="sweep-line" />}
      </div>
    </header>
  )
}
