"""
SSL/TLS Analyzer.
Checks: HTTPS usage, certificate validity (expiry, hostname match), and negotiated
TLS version. Uses Python's built-in ssl + socket modules (no extra dependency).
"""
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from app.detectors.base import BaseDetector

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


class SSLTLSDetector(BaseDetector):
    module_name = "ssl_tls"

    def _check_host(self, hostname: str, url: str):
        if urlparse(url).scheme != "https":
            self._add(
                title="Site not served over HTTPS",
                severity="HIGH",
                confidence="CONFIRMED",
                url=url,
                remediation="Serve all traffic over HTTPS and redirect HTTP to HTTPS. "
                            "Obtain a certificate (e.g. via Let's Encrypt) and enable HSTS.",
            )
            return

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()

            if tls_version in WEAK_TLS_VERSIONS:
                self._add(
                    title=f"Weak TLS version negotiated: {tls_version}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    url=url,
                    evidence={"tls_version": tls_version},
                    remediation="Disable TLS 1.0/1.1 and SSLv2/3 on the server; support TLS 1.2+ only.",
                )

            expiry_str = cert.get("notAfter")
            if expiry_str:
                expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                if days_left < 0:
                    self._add(
                        title="SSL certificate has expired",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        url=url,
                        evidence={"expired_on": expiry_str},
                        remediation="Renew the SSL certificate immediately.",
                    )
                elif days_left < 15:
                    self._add(
                        title=f"SSL certificate expires soon ({days_left} days)",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        url=url,
                        evidence={"expires_on": expiry_str},
                        remediation="Renew the SSL certificate before expiry; consider automated renewal.",
                    )

        except ssl.SSLCertVerificationError as e:
            self._add(
                title="SSL certificate verification failed",
                severity="CRITICAL",
                confidence="CONFIRMED",
                url=url,
                evidence={"error": str(e)},
                remediation="Install a valid certificate signed by a trusted CA matching the hostname.",
            )
        except Exception as e:
            self._add(
                title="Could not establish/verify TLS connection",
                severity="LOW",
                confidence="POSSIBLE",
                url=url,
                evidence={"error": str(e)},
                remediation="Manually verify TLS configuration; connection could not be tested automatically.",
            )

    def run(self):
        checked_hosts = set()
        for page in self.pages:
            hostname = urlparse(page["url"]).hostname
            if hostname in checked_hosts:
                continue
            checked_hosts.add(hostname)
            self._check_host(hostname, page["url"])
        return self.findings
