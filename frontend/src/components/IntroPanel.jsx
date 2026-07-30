const EXAMPLE_TARGETS = [
  { label: 'demo.testfire.net', url: 'http://demo.testfire.net' },
]

export default function IntroPanel({ onPickExample }) {
  return (
    <div className="intro">
      <p className="intro-lede">
        WebShield crawls a website, discovers pages and forms, and checks for
        common OWASP issues — SQL injection, reflected XSS, missing
        security headers, insecure cookies, weak SSL/TLS, and exposed
        sensitive files. Nothing here is exploited or altered on the target.
        It follows these steps :
      </p>

      <div className="how-it-works">
        {['Crawl', 'Detect', 'Score', 'Report'].map((step, i) => (
          <div className="how-step" key={step}>
            <span className="how-index">{String(i + 1).padStart(2, '0')}</span>
            <span>{step}</span>
          </div>
        ))}
      </div>

      <div className="safe-targets">
        <span className="safe-targets-label">New here? Try a safe practice target:</span>
        <div className="chip-row">
          {EXAMPLE_TARGETS.map(t => (
            <button
              key={t.url}
              type="button"
              className="chip"
              onClick={() => onPickExample(t.url)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
