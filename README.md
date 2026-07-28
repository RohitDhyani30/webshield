# WebShield — DAST Vulnerability Scanner

Non-exploitative Dynamic Application Security Testing tool. Crawls a target site,
discovers pages/forms, runs 6 detection modules, calculates a risk score, and
generates HTML/PDF reports.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # adjust limits if needed
python run.py
```

API docs (Swagger UI): http://localhost:8000/docs

## Usage (via API / Swagger)

1. **Start a scan** — `POST /api/scans`
   ```json
   {
     "target_url": "http://testphp.vulnweb.com",
     "consent_confirmed": true
   }
   ```
   `consent_confirmed` MUST be true — you must own the target or have written permission.
   **Do not scan third-party sites without authorization.** Use a deliberately
   vulnerable practice target for demos, e.g. `testphp.vulnweb.com` or a local
   OWASP Juice Shop / DVWA instance.

2. **Get results** — `GET /api/scans/{scan_id}`
3. **Download HTML report** — `GET /api/scans/{scan_id}/report/html`
4. **Download PDF report** — `GET /api/scans/{scan_id}/report/pdf`
5. **List all past scans** — `GET /api/scans`

## Modules (v1 scope)

| Module | Technique | Notes |
|---|---|---|
| Crawler | BFS same-domain crawl | max_pages / max_depth / delay configurable |
| SQL Injection | Error-based detection | GET params + GET forms only |
| XSS | Reflected-only | unique marker + unescaped-reflection check |
| Security Headers | Presence check | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Cookies | Attribute check | Secure, HttpOnly, SameSite |
| SSL/TLS | Cert + protocol check | expiry, hostname match, weak TLS version |
| Information Disclosure | Path probing | .env, .git, backups, phpinfo, etc. |

**Explicitly out of scope for v1** (documented as future work):
Open Redirect, Directory Traversal, boolean/time-based blind SQLi, DOM-based & stored XSS.

## Risk Scoring

`raw_score = Σ (severity_weight × confidence_multiplier)`, capped at 100.
`security_score = 100 − raw_score`. See `app/risk_engine.py` for exact weights and bucket thresholds.

## Project Structure

```
webshield/
├── app/
│   ├── main.py            # FastAPI app + startup
│   ├── config.py          # settings from .env
│   ├── database.py        # SQLite persistence
│   ├── schemas.py          # Pydantic models
│   ├── scanner.py          # orchestrates crawl -> detect -> score -> store
│   ├── risk_engine.py       # scoring formula
│   ├── report_generator.py  # HTML + PDF report generation
│   ├── crawler/crawler.py    # website crawler + form discovery
│   ├── detectors/           # one file per detection module
│   ├── templates/report.html
│   └── api/routes.py
├── reports/                # generated reports land here
├── requirements.txt
├── .env.example
└── run.py
```

## Frontend (React + Vite)

A minimal dashboard lives in `frontend/`. Run it alongside the backend:

```bash
cd frontend
npm install
npm run dev
```

Opens on `http://localhost:5173`. The dev server proxies `/api/*` to the FastAPI
backend on `http://localhost:8000` (see `frontend/vite.config.js`) — so make sure
`python run.py` is running in another terminal first.

Flow: enter a target URL → confirm consent → run scan → severity summary +
filterable findings table → download HTML/PDF report → browse past scans.

## Legal/Ethical Note

This tool is for authorized security testing only. Scanning systems without
permission may violate the IT Act (India) / CFAA (US) / similar laws elsewhere.
