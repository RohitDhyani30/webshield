"""
Risk Assessment Engine.

Formula (CVSS-lite, explain this exact logic in the viva):

    raw_score = sum( severity_weight(finding) * confidence_multiplier(finding) )
    normalized_score = min(100, raw_score)          # cap at 100
    security_score = 100 - normalized_score         # higher = more secure
    risk_level = bucket(normalized_score)

Severity weights (config.py):  CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
Confidence multipliers:        CONFIRMED=1.0, LIKELY=0.7, POSSIBLE=0.4

This keeps the score explainable and reproducible — a core requirement when you're
asked "how did you get this number" in a viva.
"""
from app.config import settings

CONFIDENCE_MULTIPLIERS = {
    "CONFIRMED": 1.0,
    "LIKELY": 0.7,
    "POSSIBLE": 0.4,
}


def calculate_risk(findings: list[dict]):
    raw_score = 0.0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        weight = settings.SEVERITY_WEIGHTS.get(f["severity"], 0)
        multiplier = CONFIDENCE_MULTIPLIERS.get(f["confidence"], 0.5)
        raw_score += weight * multiplier
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    normalized_score = min(100, round(raw_score, 2))
    security_score = round(100 - normalized_score, 2)

    if normalized_score >= 70 or severity_counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
    elif normalized_score >= 40:
        risk_level = "HIGH"
    elif normalized_score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "raw_risk_score": normalized_score,
        "security_score": security_score,   # 0-100, higher = safer; nice for a dashboard gauge
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
    }
