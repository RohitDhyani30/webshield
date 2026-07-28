"""
Information Disclosure Scanner.
Probes for commonly exposed sensitive files/paths at the domain root.
This is read-only (GET requests to well-known paths) — no exploitation.
"""
import requests
from urllib.parse import urljoin

from app.detectors.base import BaseDetector
from app.config import settings

SENSITIVE_PATHS = {
    ".env": "CRITICAL",
    ".git/config": "CRITICAL",
    ".git/HEAD": "CRITICAL",
    "robots.txt": "LOW",
    "sitemap.xml": "LOW",
    "backup.zip": "HIGH",
    "wp-config.php.bak": "CRITICAL",
    "config.php.bak": "CRITICAL",
    ".DS_Store": "MEDIUM",
    "phpinfo.php": "HIGH",
    ".htaccess": "MEDIUM",
    "server-status": "MEDIUM",
}


class InformationDisclosureDetector(BaseDetector):
    module_name = "information_disclosure"

    def run(self):
        if not self.pages:
            return self.findings
        base_url = self.pages[0]["url"]

        for path, severity in SENSITIVE_PATHS.items():
            test_url = urljoin(base_url, "/" + path)
            try:
                resp = self.session.get(test_url, timeout=settings.REQUEST_TIMEOUT_SECONDS)
            except requests.RequestException:
                continue

            if resp.status_code == 200 and len(resp.content) > 0:
                # robots.txt / sitemap.xml being present is expected/benign — informational only
                confidence = "CONFIRMED" if path not in ("robots.txt", "sitemap.xml") else "CONFIRMED"
                self._add(
                    title=f"Exposed file/path found: /{path}",
                    severity=severity,
                    confidence=confidence,
                    url=test_url,
                    evidence={"status_code": resp.status_code, "content_length": len(resp.content)},
                    remediation="Remove or block public access to this file via server config "
                                "(deny rules for dotfiles, backups, and debug endpoints in production).",
                )
        return self.findings
