from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


class ScanCreateRequest(BaseModel):
    target_path: str = Field(..., description="Absolute or relative path of project to scan")
    language: Optional[str] = Field(None, description="Optional language filter (python, javascript)")
    fail_on_severity: Optional[str] = Field(None, description="Severity threshold for failure check")


class AIExplanationSchema(BaseModel):
    summary: str
    root_cause: str
    why_dangerous: str
    potential_impact: str
    recommended_fix: str
    secure_example: str
    provider_name: str = "Built-In Security Engine"
    model_name: str = "Rule-Based"
    is_ai_generated: bool = False


class FindingSchema(BaseModel):
    id: Optional[str] = None
    scan_id: Optional[str] = None
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    language: str
    file_path: str
    line_number: int
    column_number: int = 0
    end_line: int = 0
    code_snippet: str = ""
    message: str
    confidence: float = 1.0
    owasp_category: str = "Uncategorized"
    recommendation: str = ""
    references: List[str] = []
    fingerprint: str
    detection_source: str = "FORGE_CUSTOM_AST"
    ai_explanation: Optional[AIExplanationSchema] = None

    model_config = ConfigDict(from_attributes=True)



class ScanSummarySchema(BaseModel):
    id: str
    target_path: str
    status: str
    scanned_files_count: int
    scanned_lines_count: int
    total_findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    duration_ms: float
    created_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(from_attributes=True)


class ScanReportSchema(BaseModel):
    summary: ScanSummarySchema
    findings: List[FindingSchema]
    parser_errors: List[str] = []


class RuleMetadataSchema(BaseModel):
    rule_id: str
    name: str
    description: str
    language: str
    severity: str
    owasp_category: str
    confidence: float
    recommendation: str
    references: List[str] = []

