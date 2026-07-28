"""
API routes. Kept thin — all real logic lives in scanner.py / risk_engine.py / report_generator.py.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse

from app.schemas import ScanRequest, ScanResultOut, FindingOut
from app import database as db
from app.scanner import run_scan
from app.risk_engine import calculate_risk
from app.report_generator import generate_html_report, generate_pdf_report
from app.config import settings

router = APIRouter()


@router.post("/scans", response_model=dict)
def start_scan(req: ScanRequest):
    if settings.REQUIRE_CONSENT and not req.consent_confirmed:
        raise HTTPException(
            status_code=403,
            detail="consent_confirmed must be true. Only scan sites you own or have written permission to test.",
        )

    # Synchronous for simplicity/viva-demo predictability. For production, move to
    # BackgroundTasks or a task queue (Celery/RQ) so the API returns immediately.
    scan_id = run_scan(str(req.target_url), max_pages=req.max_pages, max_depth=req.max_depth)
    return {"scan_id": scan_id, "status": "completed"}


@router.get("/scans", response_model=list)
def list_all_scans():
    return db.list_scans()


@router.get("/scans/{scan_id}", response_model=ScanResultOut)
def get_scan_result(scan_id: int):
    scan, findings = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    risk = calculate_risk(findings) if findings else {
        "security_score": 100, "risk_level": "LOW",
    }

    return ScanResultOut(
        scan_id=scan["id"],
        target_url=scan["target_url"],
        status=scan["status"],
        pages_crawled=scan["pages_crawled"],
        forms_found=scan["forms_found"],
        risk_score=scan["risk_score"],
        risk_level=scan["risk_level"],
        findings=[FindingOut(**f) for f in findings],
    )


@router.get("/scans/{scan_id}/report/html")
def download_html_report(scan_id: int):
    scan, findings = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    risk = calculate_risk(findings)
    path = generate_html_report(scan, findings, risk)
    return FileResponse(path, media_type="text/html", filename=f"webshield_report_{scan_id}.html")


@router.get("/scans/{scan_id}/report/pdf")
def download_pdf_report(scan_id: int):
    scan, findings = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    risk = calculate_risk(findings)
    path = generate_pdf_report(scan, findings, risk)
    return FileResponse(path, media_type="application/pdf", filename=f"webshield_report_{scan_id}.pdf")
