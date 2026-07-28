"""
Cookie Analyzer.
Verifies Secure, HttpOnly, and SameSite attributes on cookies set by the target.
Uses the raw Set-Cookie header captured per page (requests' response.cookies loses
attribute detail, so we parse Set-Cookie manually where available).
"""
from app.detectors.base import BaseDetector


class CookieDetector(BaseDetector):
    module_name = "cookie_security"

    def run(self):
        seen_cookies = set()
        for page in self.pages:
            raw_headers = page.get("headers", {})
            set_cookie = raw_headers.get("Set-Cookie") or raw_headers.get("set-cookie")
            if not set_cookie:
                continue

            cookie_name = set_cookie.split("=")[0].strip()
            if cookie_name in seen_cookies:
                continue
            seen_cookies.add(cookie_name)

            lowered = set_cookie.lower()
            missing = []
            if "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")

            if missing:
                severity = "HIGH" if "HttpOnly" in missing else "MEDIUM"
                self._add(
                    title=f"Cookie '{cookie_name}' missing attribute(s): {', '.join(missing)}",
                    severity=severity,
                    confidence="CONFIRMED",
                    url=page["url"],
                    evidence={"cookie": cookie_name, "missing_attributes": missing},
                    remediation="Set Secure (HTTPS-only), HttpOnly (blocks JS/XSS access), and "
                                "SameSite=Lax/Strict (CSRF mitigation) on all session cookies.",
                )
        return self.findings
