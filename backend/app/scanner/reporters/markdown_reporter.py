from typing import List
from backend.app.schemas.scan import ScanSummarySchema, FindingSchema


class MarkdownReporter:
    @staticmethod
    def generate_report(summary: ScanSummarySchema, findings: List[FindingSchema], parser_errors: List[str] = None) -> str:
        lines = []
        lines.append("# FORGE — Security Analysis Report")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- **Target Path**: `{summary.target_path}`")
        lines.append(f"- **Scan ID**: `{summary.id}`")
        lines.append(f"- **Status**: `{summary.status}`")
        lines.append(f"- **Scanned Files**: {summary.scanned_files_count}")
        lines.append(f"- **Scanned Lines**: {summary.scanned_lines_count}")
        lines.append(f"- **Total Findings**: {summary.total_findings_count}")
        lines.append(f"- **Scan Duration**: {summary.duration_ms:.2f} ms")
        lines.append("")

        lines.append("### Severity Breakdown")
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        lines.append(f"| **CRITICAL** | {summary.critical_count} |")
        lines.append(f"| **HIGH** | {summary.high_count} |")
        lines.append(f"| **MEDIUM** | {summary.medium_count} |")
        lines.append(f"| **LOW** | {summary.low_count} |")
        lines.append(f"| **INFO** | {summary.info_count} |")
        lines.append("")

        if parser_errors:
            lines.append("### Parser Errors / Warnings")
            for err in parser_errors:
                lines.append(f"- :warning: {err}")
            lines.append("")

        lines.append("## Security Findings")
        if not findings:
            lines.append("No security vulnerabilities detected.")
        else:
            for idx, f in enumerate(findings, 1):
                lines.append(f"### {idx}. [{f.severity}] {f.title} (`{f.rule_id}`)")
                lines.append(f"- **OWASP Category**: {f.owasp_category}")
                lines.append(f"- **Location**: `{f.file_path}` : line {f.line_number}")
                lines.append(f"- **Message**: {f.message}")
                if f.code_snippet:
                    lines.append("```python")
                    lines.append(f.code_snippet)
                    lines.append("```")
                lines.append(f"**Recommendation**: {f.recommendation}")
                lines.append("")

        return "\n".join(lines)
