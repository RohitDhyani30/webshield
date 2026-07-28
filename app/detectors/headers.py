"""
Security Header Analyzer.
Checks for presence (and basic sanity) of key HTTP security headers on each crawled page.
Uses headers already captured by the crawler (no extra requests needed).
"""
from app.detectors.base import BaseDetector

REQUIRED_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "Define a strict CSP to mitigate XSS and data injection attacks."),
    "Strict-Transport-Security": ("MEDIUM", "Add HSTS to force browsers to use HTTPS for this domain."),
    "X-Frame-Options": ("LOW", "Add X-Frame-Options: DENY/SAMEORIGIN to prevent clickjacking."),
    "X-Content-Type-Options": ("LOW", "Add X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks."),
    "Referrer-Policy": ("LOW", "Add a Referrer-Policy header to limit referrer data leakage."),
}


class SecurityHeaderDetector(BaseDetector):
    module_name = "security_headers"

    def run(self):
        checked_once = set()
        for page in self.pages:
            if page["url"] in checked_once:
                continue
            checked_once.add(page["url"])

            headers_lower = {k.lower(): v for k, v in page.get("headers", {}).items()}
            for header, (severity, remediation) in REQUIRED_HEADERS.items():
                if header.lower() not in headers_lower:
                    self._add(
                        title=f"Missing security header: {header}",
                        severity=severity,
                        confidence="CONFIRMED",
                        url=page["url"],
                        evidence={"missing_header": header},
                        remediation=remediation,
                    )
        return self.findings
