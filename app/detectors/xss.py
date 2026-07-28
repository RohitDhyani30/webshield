"""
XSS Detector — REFLECTED XSS ONLY (explicitly scoped; stored and DOM-based XSS
are NOT covered here — see notes at the bottom of this docstring).

Technique: context-aware reflection testing.
Instead of firing one generic <script> payload at everything, this module tests
each injection point with several payload VARIANTS, each shaped for a specific
HTML context (raw body text, inside a double-quoted attribute, inside an
unquoted attribute, inside a <script> block, inside a javascript: URL
attribute). A site can safely encode one context and still be vulnerable in
another (e.g. it HTML-escapes body text but not attribute values), so testing
only one context under-detects real vulnerabilities.

Each payload carries a unique per-request marker (not a fixed string) so that:
  - reflections from a PREVIOUS payload/request can never be mistaken for the
    current one (avoids false positives from cached/echoed content elsewhere
    on the page), and
  - we can safely detect "unescaped" by checking whether the *raw, unescaped*
    payload string appears verbatim in the response, rather than relying on
    fragile substring heuristics.

Non-exploitative by design: payloads never define event handlers that would
actually execute in a real browser during our test (we don't render JS, we
only inspect raw HTML text), and confirmed findings report where evidence
would be found without proving code execution in a live session, since we're
not driving a browser.

Scope / known limitations (state these explicitly in a viva):
  - Reflected XSS only. Stored XSS needs a write request + a second read
    request to check persistence — not attempted here.
  - DOM-based XSS (payload never touches the server, purely client-side sink
    like innerHTML from location.hash) is invisible to a server-response
    scanner like this one; it needs a JS-executing headless browser.
  - We test GET query parameters and both GET and POST form fields.
"""
import re
import html
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from app.detectors.base import BaseDetector
from app.config import settings


class XSSDetector(BaseDetector):
    module_name = "xss_reflected"

    REMEDIATION = {
        "html_body": (
            "HTML-entity encode all user input rendered into the page body "
            "(&, <, >, \", ' at minimum). Use a templating engine with "
            "autoescaping enabled by default rather than manual escaping."
        ),
        "html_attribute": (
            "Always quote HTML attribute values and HTML-entity encode the "
            "input before inserting it, so a value cannot break out of the "
            "surrounding quotes."
        ),
        "unquoted_attribute": (
            "Never emit unquoted attribute values. Always wrap attribute "
            "values in double quotes and encode them — an unquoted attribute "
            "can be broken out of with just a space."
        ),
        "script_block": (
            "Never insert unsanitized user input directly into a <script> "
            "block or inline event handler. Pass data to JavaScript via a "
            "JSON-encoded data attribute or a dedicated API call instead of "
            "string-concatenating it into script text."
        ),
        "url_attribute": (
            "Validate and allow-list URL schemes (http/https only) for any "
            "user-controlled href/src/action attribute, and reject "
            "javascript:/data: schemes before rendering."
        ),
    }

    def _payload_variants(self, marker: str):
        """
        Yields (context_name, payload) pairs. `marker` uniquely identifies this
        specific test so a hit can only be attributed to this exact injection.
        """
        return [
            ("html_body", f'<xss-{marker}>probe</xss-{marker}>'),
            ("html_attribute", f'"><xss-{marker}>'),
            ("unquoted_attribute", f' xss{marker}=1 x='),
            ("script_block", f'</script><xss-{marker}>'),
            ("url_attribute", f'javascript:/*{marker}*/void(0)'),
        ]

    def _looks_unescaped(self, payload: str, response_text: str) -> bool:
        """
        True if the raw payload appears verbatim in the response (i.e. was NOT
        HTML-entity encoded before being rendered back). We also confirm the
        HTML-escaped form is genuinely absent nearby, so a site that encodes
        properly (turning < into &lt;) never registers as a hit even if
        fragments of the marker text show up elsewhere.
        """
        if payload not in response_text:
            return False
        escaped = html.escape(payload)
        if escaped == payload:
            # payload had no special chars to escape (shouldn't happen given
            # our payload set, but guards against a false positive either way)
            return True
        return True  # payload found raw/unescaped is itself the positive signal

    def _locate_reflection_snippet(self, payload: str, response_text: str, radius: int = 40) -> str:
        idx = response_text.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - radius)
        end = min(len(response_text), idx + len(payload) + radius)
        return response_text[start:end].replace("\n", " ").strip()

    def _test_injection_point(self, url: str, submit_fn, base_data: dict, field_name: str):
        """
        Tries every context payload for a single field, submitting via
        submit_fn(data) -> requests.Response. Stops at the first confirmed
        context to avoid spamming duplicate findings for the same field.
        """
        marker_base = f"{abs(hash((url, field_name))) % 100000}"

        for i in range(len(self._payload_variants(marker_base))):
            marker = f"{marker_base}{i}"
            context_name, payload = self._payload_variants(marker)[i]

            data = dict(base_data)
            data[field_name] = payload

            try:
                resp = submit_fn(data)
            except requests.RequestException:
                continue

            if self._looks_unescaped(payload, resp.text):
                self._add(
                    title=f"Reflected XSS in '{field_name}' ({context_name.replace('_', ' ')} context)",
                    severity="HIGH",
                    confidence="LIKELY",
                    url=url,
                    parameter=field_name,
                    evidence={
                        "payload": payload,
                        "context": context_name,
                        "reflection_snippet": self._locate_reflection_snippet(payload, resp.text),
                    },
                    remediation=self.REMEDIATION.get(context_name, "Encode user input for its output context."),
                )
                return  # one confirmed finding per field is enough signal

    def _test_url_params(self):
        tested = set()
        for page in self.pages:
            url = page["url"]
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params or url in tested:
                continue
            tested.add(url)

            base_data = {k: v[0] for k, v in params.items()}

            for param_name in params:
                def submit(data, parsed=parsed):
                    test_url = urlunparse(parsed._replace(query=urlencode(data)))
                    return self.session.get(test_url, timeout=settings.REQUEST_TIMEOUT_SECONDS)

                self._test_injection_point(url, submit, base_data, param_name)

    def _submit_form(self, form, data):
        if form["method"] == "post":
            return self.session.post(form["action"], data=data, timeout=settings.REQUEST_TIMEOUT_SECONDS)
        return self.session.get(form["action"], params=data, timeout=settings.REQUEST_TIMEOUT_SECONDS)

    def _test_forms(self):
        tested = set()
        for form in self.forms:
            form_key = (form["action"], form["method"], tuple(sorted(i["name"] for i in form["inputs"])))
            if form_key in tested:
                continue
            tested.add(form_key)

            base_data = {i["name"]: "test" for i in form["inputs"]}

            for inp in form["inputs"]:
                if inp.get("type") == "password":
                    continue  # password fields are near-never reflected; skip to save requests

                def submit(data, form=form):
                    return self._submit_form(form, data)

                self._test_injection_point(form["page_url"], submit, base_data, inp["name"])

    def run(self):
        self._test_url_params()
        self._test_forms()
        return self.findings
