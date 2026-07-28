"""
Scan Orchestrator — ties crawler, detectors, risk engine, and DB together.
This is the "controller" the API layer calls; keeping it separate from routes.py
makes it testable and reusable (e.g. from a CLI script too).
"""
from app.crawler.crawler import Crawler
from app.detectors.sqli import SQLiDetector
from app.detectors.xss import XSSDetector
from app.detectors.headers import SecurityHeaderDetector
from app.detectors.cookies import CookieDetector
from app.detectors.ssl_tls import SSLTLSDetector
from app.detectors.info_disclosure import InformationDisclosureDetector
from app.risk_engine import calculate_risk
from app import database as db


DETECTOR_CLASSES = [
    SQLiDetector,
    XSSDetector,
    SecurityHeaderDetector,
    CookieDetector,
    SSLTLSDetector,
    InformationDisclosureDetector,
]


def run_scan(target_url: str, max_pages: int = None, max_depth: int = None) -> int:
    scan_id = db.create_scan(target_url)

    crawler = Crawler(target_url, max_pages=max_pages, max_depth=max_depth)
    pages, forms = crawler.crawl()

    all_findings = []
    for DetectorClass in DETECTOR_CLASSES:
        detector = DetectorClass(crawler.session, pages, forms)
        try:
            findings = detector.run()
        except Exception as e:
            # A single detector failing should never take down the whole scan.
            findings = [{
                "module": DetectorClass.module_name,
                "title": f"Detector error: {e}",
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "url": target_url,
                "parameter": None,
                "evidence": {},
                "remediation": "Internal error — module did not complete. Re-run scan.",
            }]
        all_findings.extend(findings)

    for finding in all_findings:
        db.add_finding(scan_id, finding)

    risk = calculate_risk(all_findings)
    db.finish_scan(
        scan_id,
        pages_crawled=len(pages),
        forms_found=len(forms),
        risk_score=risk["raw_risk_score"],
        risk_level=risk["risk_level"],
    )

    return scan_id
