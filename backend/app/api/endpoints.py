from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, status
from sqlalchemy.orm import Session

from backend.app.models.db import SessionLocal, ScanModel, FindingModel, init_db
from backend.app.schemas.scan import (
    ScanCreateRequest,
    ScanReportSchema,
    ScanSummarySchema,
    FindingSchema,
    RuleMetadataSchema
)
from backend.app.scanner.engine import ScannerEngine
from backend.app.scanner.rules import get_all_registered_rules
from backend.app.scanner.file_discovery import FileDiscoveryError

router = APIRouter()

# Ensure DB tables are initialized
init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



from backend.app.ai.factory import get_llm_provider

@router.get("/ai/status", tags=["AI Integration"])
def get_ai_status():
    provider = get_llm_provider()
    is_avail = provider.is_available()
    return {
        "provider": getattr(provider, "model", "Rule-Based"),
        "is_available": is_avail,
        "base_url": getattr(provider, "base_url", "N/A"),
        "message": "Local Ollama LLM Active" if is_avail else "AI explanation unavailable. Showing rule-based security analysis."
    }


@router.get("/health", tags=["Health"])
def health_check():

    return {
        "status": "healthy",
        "service": "FORGE Security Platform Engine",
        "version": "0.1.0"
    }


@router.post("/scans", response_model=ScanReportSchema, status_code=status.HTTP_201_CREATED, tags=["Scans"])
def create_scan(request: ScanCreateRequest, db: Session = Depends(get_db)):
    try:
        engine = ScannerEngine()
        report = engine.run_scan(
            target_path=request.target_path,
            language_filter=request.language,
            save_to_db=True
        )
        return report
    except FileDiscoveryError as fde:
        raise HTTPException(status_code=400, detail=str(fde))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scan failure: {str(e)}")


@router.get("/scans/{scan_id}", response_model=ScanSummarySchema, tags=["Scans"])
def get_scan_by_id(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=List[FindingSchema], tags=["Scans"])
def get_findings_by_scan_id(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")
    
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
    return findings


@router.get("/findings/{finding_id}", response_model=FindingSchema, tags=["Findings"])
def get_finding_details(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding ID '{finding_id}' not found.")
    return finding


@router.get("/rules", response_model=List[RuleMetadataSchema], tags=["Rules"])
def list_security_rules():
    rules = get_all_registered_rules()
    return [
        RuleMetadataSchema(
            rule_id=r.rule_id,
            name=r.name,
            description=r.description,
            language=r.language,
            severity=r.severity,
            owasp_category=r.owasp_category,
            confidence=r.confidence,
            recommendation=r.recommendation,
            references=r.references
        ) for r in rules
    ]
