import json
from typing import Dict, Any, List
from backend.app.schemas.scan import ScanReportSchema, ScanSummarySchema, FindingSchema


class JSONReporter:
    @staticmethod
    def generate_report(summary: ScanSummarySchema, findings: List[FindingSchema], parser_errors: List[str] = None) -> str:
        report_data = {
            "forge_version": "0.1.0",
            "scan_info": {
                "scan_id": summary.id,
                "target_path": summary.target_path,
                "status": summary.status,
                "created_at": summary.created_at.isoformat() if hasattr(summary.created_at, "isoformat") else str(summary.created_at),
                "duration_ms": round(summary.duration_ms, 2),
            },
            "statistics": {
                "scanned_files_count": summary.scanned_files_count,
                "scanned_lines_count": summary.scanned_lines_count,
                "total_findings_count": summary.total_findings_count,
                "severity_summary": {
                    "CRITICAL": summary.critical_count,
                    "HIGH": summary.high_count,
                    "MEDIUM": summary.medium_count,
                    "LOW": summary.low_count,
                    "INFO": summary.info_count,
                }
            },
            "parser_errors": parser_errors or [],
            "findings": [finding.model_dump() if hasattr(finding, "model_dump") else finding for finding in findings]
        }
        return json.dumps(report_data, indent=2)
