from abc import ABC, abstractmethod
import ast
import hashlib
from typing import List, Optional, Dict, Any


class FindingData:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        language: str,
        file_path: str,
        line_number: int,
        column_number: int = 0,
        end_line: int = 0,
        code_snippet: str = "",
        message: str = "",
        confidence: float = 1.0,
        owasp_category: str = "Uncategorized",
        recommendation: str = "",
        references: Optional[List[str]] = None,
        detection_source: str = "FORGE_CUSTOM_AST",
        ai_explanation: Optional[Dict[str, Any]] = None
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.language = language
        self.file_path = file_path
        self.line_number = line_number
        self.column_number = column_number
        self.end_line = end_line or line_number
        self.code_snippet = code_snippet.strip()
        self.message = message
        self.confidence = confidence
        self.owasp_category = owasp_category
        self.recommendation = recommendation
        self.references = references or []
        self.detection_source = detection_source
        self.ai_explanation = ai_explanation
        self.fingerprint = self.generate_fingerprint()

    def generate_fingerprint(self) -> str:
        """
        Generates a stable SHA-256 fingerprint for finding deduplication.
        Fingerprint = SHA256(rule_id + normalized_file_path + line_number + clean_code_snippet)
        """
        normalized_path = self.file_path.replace("\\", "/").lower()
        clean_snippet = "".join(self.code_snippet.split())
        raw_str = f"{self.rule_id}:{normalized_path}:{self.line_number}:{clean_snippet}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "language": self.language,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "end_line": self.end_line,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "confidence": self.confidence,
            "owasp_category": self.owasp_category,
            "recommendation": self.recommendation,
            "references": self.references,
            "fingerprint": self.fingerprint,
            "detection_source": self.detection_source,
            "ai_explanation": self.ai_explanation,
        }



class BaseRule(ABC):
    rule_id: str = "BASE-000"
    name: str = "Base Security Rule"
    description: str = "Base rule class"
    language: str = "python"
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    owasp_category: str = "A03:2021 Injection"
    confidence: float = 0.90
    recommendation: str = "Review code for security compliance."
    references: List[str] = []

    def get_built_in_explanation(self) -> Dict[str, str]:
        """Provides default non-AI structured explanation."""
        return {
            "summary": f"{self.name} ({self.rule_id})",
            "root_cause": self.description,
            "why_it_is_dangerous": f"This vulnerability falls under OWASP Category {self.owasp_category} and poses security risks if exploited.",
            "potential_impact": f"Severity level: {self.severity}. Unauthenticated or unauthorized attackers could compromise security invariants.",
            "recommended_fix": self.recommendation,
            "secure_example": "Use standard parameterized interfaces or secure built-in methods."
        }

    def analyze_python_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        """Analyzes Python AST tree. Returns findings list or empty list if not applicable."""
        return []

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        """Analyzes JavaScript AST tree. Returns findings list or empty list if not applicable."""
        return []

