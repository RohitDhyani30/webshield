"""
SQL Injection Detector (non-exploitative).

Two techniques, covering the two most common real-world cases:

1. ERROR-BASED — inject payloads designed to break SQL syntax, then scan the
   response for known DB error signatures. Works on GET params and GET/POST forms.

2. AUTH-BYPASS (differential) — for login-style forms (a field of type=password
   present). Sends a baseline request with an obviously-wrong credential pair,
   then a request with a classic always-true payload (e.g. ' OR '1'='1'--) in the
   username/email field. If the payload response looks like a SUCCESSFUL login
   while the baseline looks like a FAILED one, that's a strong signal of an
   authentication-bypass SQLi — even though no DB error is ever shown. This is
   the technique needed to catch injectable login forms (e.g. DVWA, bWAPP,
   classic PHP login forms). We do NOT attempt full boolean/time-based blind
   SQLi on arbitrary parameters — that's flagged as future work.

KNOWN LIMITATION: this module only sees forms present in static HTML parsed by
the crawler. Single-page apps (Angular/React/Vue) that call REST/JSON APIs
directly from JS — e.g. OWASP Juice Shop's login, which POSTs JSON to
/rest/user/login instead of submitting an HTML <form> — are invisible to a
BeautifulSoup-based crawler. Testing those requires either a headless browser
(Selenium/Playwright) to render JS and capture XHR calls, or manually targeting
known REST endpoints (see KNOWN_AUTH_ENDPOINTS below for a lightweight, explicit
workaround).
"""
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from app.detectors.base import BaseDetector
from app.config import settings

# Harmless payloads: designed to trigger a DB error, not to extract/alter data.
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]

# Classic auth-bypass payloads for username/email-style fields.
AUTH_BYPASS_PAYLOADS = ["' OR '1'='1'--", "' OR 1=1--", "admin'--", "' OR '1'='1' /*"]

# Well-known SPA REST login endpoints we can probe directly, since their forms
# aren't visible to a static HTML crawler. Add more here as needed per target.
KNOWN_AUTH_ENDPOINTS = [
    {"path": "/rest/user/login", "method": "post", "content_type": "json",
     "fields": {"email": "", "password": "x"}},
]

# Signatures pulled from common DB error strings (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax.*mysql",
    "pg_query()",
    "postgresql.*error",
    "sqlite3.operationalerror",
    "sqlite_error",
    "microsoft ole db provider for odbc drivers",
    "ora-01756",
    "unterminated string literal",
]


class SQLiDetector(BaseDetector):
    module_name = "sql_injection"

    def _has_db_error(self, text: str) -> bool:
        lowered = text.lower()
        return any(sig in lowered for sig in DB_ERROR_SIGNATURES)

    def _test_url_params(self):
        tested_urls = set()
        for page in self.pages:
            url = page["url"]
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params or url in tested_urls:
                continue
            tested_urls.add(url)

            for param_name in params:
                for payload in SQLI_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        resp = self.session.get(test_url, timeout=settings.REQUEST_TIMEOUT_SECONDS)
                    except requests.RequestException:
                        continue

                    if self._has_db_error(resp.text):
                        self._add(
                            title=f"Possible SQL Injection in parameter '{param_name}'",
                            severity="CRITICAL",
                            confidence="LIKELY",
                            url=url,
                            parameter=param_name,
                            evidence={"payload": payload, "matched_signature": True},
                            remediation="Use parameterized queries / prepared statements. "
                                        "Never concatenate user input into SQL strings. "
                                        "Apply least-privilege DB accounts and disable verbose DB error output in production.",
                        )
                        break  # one confirmed hit per param is enough

    def _submit_form(self, form, data):
        """Submit a form via GET or POST, matching its declared method."""
        if form["method"] == "post":
            return self.session.post(form["action"], data=data,
                                      timeout=settings.REQUEST_TIMEOUT_SECONDS)
        return self.session.get(form["action"], params=data,
                                 timeout=settings.REQUEST_TIMEOUT_SECONDS)

    def _test_forms_error_based(self):
        """Error-based check — now covers GET and POST forms."""
        for form in self.forms:
            for inp in form["inputs"]:
                if inp.get("type") == "password":
                    continue  # password fields go through the auth-bypass check instead
                for payload in SQLI_PAYLOADS:
                    data = {i["name"]: "test" for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        resp = self._submit_form(form, data)
                    except requests.RequestException:
                        continue
                    if self._has_db_error(resp.text):
                        self._add(
                            title=f"Possible SQL Injection in form field '{inp['name']}'",
                            severity="CRITICAL",
                            confidence="LIKELY",
                            url=form["page_url"],
                            parameter=inp["name"],
                            evidence={"form_action": form["action"], "payload": payload,
                                      "method": form["method"]},
                            remediation="Use parameterized queries / prepared statements for all form inputs.",
                        )
                        break

    def _looks_like_failed_login(self, resp) -> bool:
        fail_markers = ["invalid", "incorrect", "failed", "denied", "not found", "error"]
        lowered = resp.text.lower()
        return resp.status_code in (401, 403) or any(m in lowered for m in fail_markers)

    def _test_auth_bypass_forms(self):
        """
        Differential auth-bypass check: only runs on forms that have a password
        field (i.e. login forms). Compares a baseline invalid-credential request
        against a request using a classic always-true SQLi payload in the
        username/email-style field.
        """
        for form in self.forms:
            has_password = any(i.get("type") == "password" for i in form["inputs"])
            if not has_password:
                continue

            username_field = next(
                (i["name"] for i in form["inputs"]
                 if i.get("type") in ("text", "email") or "user" in i["name"].lower()
                 or "email" in i["name"].lower()),
                None,
            )
            password_field = next((i["name"] for i in form["inputs"] if i.get("type") == "password"), None)
            if not username_field or not password_field:
                continue

            baseline_data = {i["name"]: "test" for i in form["inputs"]}
            baseline_data[username_field] = "definitely_not_a_real_user_x1"
            baseline_data[password_field] = "definitely_wrong_pw_x1"

            try:
                baseline_resp = self._submit_form(form, baseline_data)
            except requests.RequestException:
                continue
            baseline_failed = self._looks_like_failed_login(baseline_resp)

            for payload in AUTH_BYPASS_PAYLOADS:
                payload_data = {i["name"]: "test" for i in form["inputs"]}
                payload_data[username_field] = payload
                payload_data[password_field] = "irrelevant"
                try:
                    payload_resp = self._submit_form(form, payload_data)
                except requests.RequestException:
                    continue

                payload_looks_success = not self._looks_like_failed_login(payload_resp)
                status_changed = payload_resp.status_code != baseline_resp.status_code
                length_delta = abs(len(payload_resp.text) - len(baseline_resp.text))

                if baseline_failed and payload_looks_success and (status_changed or length_delta > 50):
                    self._add(
                        title=f"Possible authentication-bypass SQL Injection in '{username_field}'",
                        severity="CRITICAL",
                        confidence="LIKELY",
                        url=form["page_url"],
                        parameter=username_field,
                        evidence={
                            "payload": payload,
                            "baseline_status": baseline_resp.status_code,
                            "payload_status": payload_resp.status_code,
                            "response_length_delta": length_delta,
                        },
                        remediation="Use parameterized queries for authentication logic; never build the "
                                    "login WHERE clause via string concatenation. Use a proper ORM or "
                                    "prepared statements, and hash+verify passwords server-side rather "
                                    "than relying on the query itself to gate access.",
                    )
                    break

    def _test_known_rest_endpoints(self, base_url: str):
        """
        Probes well-known SPA REST login endpoints directly (e.g. Juice Shop's
        /rest/user/login) since these are invisible to the static HTML crawler.
        Uses the same differential logic as the HTML auth-bypass check.
        """
        for endpoint in KNOWN_AUTH_ENDPOINTS:
            url = base_url.rstrip("/") + endpoint["path"]
            try:
                baseline = self.session.post(url, json={"email": "not_a_real_user@x.com", "password": "wrongpw"},
                                              timeout=settings.REQUEST_TIMEOUT_SECONDS)
            except requests.RequestException:
                continue
            if baseline.status_code == 404:
                continue  # endpoint doesn't exist on this target, skip silently

            baseline_failed = baseline.status_code in (401, 403) or "error" in baseline.text.lower()

            for payload in AUTH_BYPASS_PAYLOADS:
                try:
                    resp = self.session.post(url, json={"email": payload, "password": "irrelevant"},
                                              timeout=settings.REQUEST_TIMEOUT_SECONDS)
                except requests.RequestException:
                    continue

                success_markers = ["token", "authentication", "bid", "id"]
                looks_success = resp.status_code == 200 and any(m in resp.text.lower() for m in success_markers)

                if baseline_failed and looks_success:
                    self._add(
                        title="Possible authentication-bypass SQL Injection in login API endpoint",
                        severity="CRITICAL",
                        confidence="LIKELY",
                        url=url,
                        parameter="email",
                        evidence={"payload": payload, "baseline_status": baseline.status_code,
                                  "payload_status": resp.status_code},
                        remediation="Use parameterized queries for authentication logic; never build the "
                                    "login WHERE clause via string concatenation.",
                    )
                    break

    def run(self):
        self._test_url_params()
        self._test_forms_error_based()
        self._test_auth_bypass_forms()
        if self.pages:
            base_url = f"{urlparse(self.pages[0]['url']).scheme}://{urlparse(self.pages[0]['url']).netloc}"
            self._test_known_rest_endpoints(base_url)
        return self.findings
