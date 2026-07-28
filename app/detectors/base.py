"""
Base class all detectors inherit from. Enforces a consistent finding format
so the risk engine and report generator don't need per-module special-casing.
"""
from abc import ABC, abstractmethod


class BaseDetector(ABC):
    module_name = "base"

    def __init__(self, session, pages, forms):
        self.session = session
        self.pages = pages
        self.forms = forms
        self.findings = []

    @abstractmethod
    def run(self):
        """Execute the check and populate self.findings. Return self.findings."""
        raise NotImplementedError

    def _add(self, title, severity, confidence, url=None, parameter=None,
              evidence=None, remediation=""):
        self.findings.append({
            "module": self.module_name,
            "title": title,
            "severity": severity,           # CRITICAL | HIGH | MEDIUM | LOW
            "confidence": confidence,        # CONFIRMED | LIKELY | POSSIBLE
            "url": url,
            "parameter": parameter,
            "evidence": evidence or {},
            "remediation": remediation,
        })
