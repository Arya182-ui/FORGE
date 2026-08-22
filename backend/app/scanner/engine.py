import time
import uuid
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from sqlalchemy.orm import Session
from datetime import datetime

from backend.app.scanner.file_discovery import FileDiscoveryService, FileDiscoveryError
from backend.app.scanner.parsers.python_ast import PythonASTParser
from backend.app.scanner.parsers.javascript_ast import JavaScriptASTParser
from backend.app.scanner.rules import get_rules_for_language
from backend.app.scanner.rules.base import FindingData
from backend.app.schemas.scan import ScanSummarySchema, FindingSchema, ScanReportSchema
from backend.app.models.db import ScanModel, FindingModel, SessionLocal
from backend.app.ai.factory import get_llm_provider


class ScannerEngine:
    def __init__(self, file_discovery_service: Optional[FileDiscoveryService] = None):
        self.file_discovery = file_discovery_service or FileDiscoveryService()

    def run_scan(
        self,
        target_path: str,
        language_filter: Optional[str] = None,
        save_to_db: bool = True
    ) -> ScanReportSchema:
        start_time = time.time()
        scan_id = str(uuid.uuid4())

        # Step 1: Discover files safely
        discovered_files = self.file_discovery.discover_files(target_path, language_filter)

        total_files = len(discovered_files)
        total_lines = 0
        all_raw_findings: List[FindingData] = []
        parser_errors: List[str] = []

        # Step 2: Parse and run security rules
        for file_path, lang in discovered_files:
            rel_path_str = str(file_path)

            if lang == "python":
                tree, source_code, line_count, err_msg = PythonASTParser.parse_file(file_path)
                total_lines += line_count

                if err_msg:
                    parser_errors.append(err_msg)
                    continue

                if tree:
                    rules = get_rules_for_language("python")
                    for rule in rules:
                        try:
                            rule_findings = rule.analyze_python_ast(tree, rel_path_str, source_code)
                            all_raw_findings.extend(rule_findings)
                        except Exception as rule_err:
                            parser_errors.append(f"Error running rule {rule.rule_id} on {file_path.name}: {str(rule_err)}")

            elif lang == "javascript":
                tree, source_code, line_count, err_msg = JavaScriptASTParser.parse_file(file_path)
                total_lines += line_count

                if err_msg:
                    parser_errors.append(err_msg)
                    continue

                if tree:
                    rules = get_rules_for_language("javascript")
                    for rule in rules:
                        try:
                            rule_findings = rule.analyze_javascript_ast(tree, rel_path_str, source_code)
                            all_raw_findings.extend(rule_findings)
                        except Exception as rule_err:
                            parser_errors.append(f"Error running JS rule {rule.rule_id} on {file_path.name}: {str(rule_err)}")

        # Step 3: Deduplicate findings using fingerprint
        seen_fingerprints = set()
        deduplicated_findings: List[FindingData] = []

        for finding in all_raw_findings:
            if finding.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(finding.fingerprint)
                deduplicated_findings.append(finding)

        # Step 3.5: AI Explanation Enrichment (Optional / Fallback)
        llm_provider = get_llm_provider()
        for finding in deduplicated_findings:
            try:
                matching_rules = get_rules_for_language(finding.language)
                rule_obj = next((r for r in matching_rules if r.rule_id == finding.rule_id), None)
                built_in_dict = rule_obj.get_built_in_explanation() if rule_obj else {}

                explanation = llm_provider.generate_explanation(
                    rule_id=finding.rule_id,
                    title=finding.title,
                    severity=finding.severity,
                    code_snippet=finding.code_snippet,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    rule_description=rule_obj.description if rule_obj else finding.message,
                    owasp_category=finding.owasp_category,
                    built_in_explanation=built_in_dict
                )
                finding.ai_explanation = explanation.model_dump()
            except Exception:
                pass  # Never allow AI failure to interrupt scan execution

        # Step 4: Calculate statistics
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for f in deduplicated_findings:
            sev = f.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1

        duration_ms = (time.time() - start_time) * 1000.0
        now_dt = datetime.utcnow()

        # Step 5: Construct summary schema
        summary_schema = ScanSummarySchema(
            id=scan_id,
            target_path=str(Path(target_path).resolve()),
            status="COMPLETED",
            scanned_files_count=total_files,
            scanned_lines_count=total_lines,
            total_findings_count=len(deduplicated_findings),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            info_count=severity_counts["INFO"],
            duration_ms=duration_ms,
            created_at=now_dt
        )

        finding_schemas = [FindingSchema(**f.to_dict(), scan_id=scan_id) for f in deduplicated_findings]

        # Step 6: Optionally save to SQLite DB
        if save_to_db:
            db: Session = SessionLocal()
            try:
                scan_record = ScanModel(
                    id=scan_id,
                    target_path=summary_schema.target_path,
                    status=summary_schema.status,
                    scanned_files_count=total_files,
                    scanned_lines_count=total_lines,
                    total_findings_count=len(deduplicated_findings),
                    critical_count=severity_counts["CRITICAL"],
                    high_count=severity_counts["HIGH"],
                    medium_count=severity_counts["MEDIUM"],
                    low_count=severity_counts["LOW"],
                    info_count=severity_counts["INFO"],
                    duration_ms=duration_ms
                )
                db.add(scan_record)

                for f_schema in finding_schemas:
                    finding_record = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        rule_id=f_schema.rule_id,
                        title=f_schema.title,
                        severity=f_schema.severity,
                        language=f_schema.language,
                        file_path=f_schema.file_path,
                        line_number=f_schema.line_number,
                        column_number=f_schema.column_number,
                        end_line=f_schema.end_line,
                        code_snippet=f_schema.code_snippet,
                        message=f_schema.message,
                        confidence=f_schema.confidence,
                        owasp_category=f_schema.owasp_category,
                        recommendation=f_schema.recommendation,
                        fingerprint=f_schema.fingerprint,
                        detection_source=f_schema.detection_source
                    )
                    db.add(finding_record)

                db.commit()
            except Exception as db_err:
                db.rollback()
                parser_errors.append(f"Database save warning: {str(db_err)}")
            finally:
                db.close()

        return ScanReportSchema(
            summary=summary_schema,
            findings=finding_schemas,
            parser_errors=parser_errors
        )
