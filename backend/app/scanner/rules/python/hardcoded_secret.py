import ast
import re
from typing import List
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonHardcodedSecretRule(BaseRule):
    rule_id = "PY-SEC-001"
    name = "Hardcoded Sensitive Secret"
    description = "Hardcoding credentials, passwords, API keys, or private tokens in source code exposes secrets to unauthorized users or repositories."
    language = "python"
    severity = "HIGH"
    owasp_category = "A07:2021 Identification and Authentication Failures"
    confidence = 0.85
    recommendation = "Load sensitive credentials securely from environment variables or a secure key management system (e.g. os.environ.get('SECRET_KEY'))."
    references = [
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    ]

    SECRET_KEYWORDS = re.compile(
        r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|jwt[_-]?secret|db[_-]?pass)",
        re.IGNORECASE
    )

    IGNORE_VALUES = {"todo", "change_me", "placeholder", "your_secret_here", "none", "", "test", "username", "admin"}

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            var_name = ""
            val_str = ""

            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val_str = node.value.value
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name):
                    var_name = node.target.id
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val_str = node.value.value

            if var_name and val_str:
                if self.SECRET_KEYWORDS.search(var_name):
                    val_clean = val_str.strip().lower()
                    if val_clean not in self.IGNORE_VALUES and len(val_str) >= 6:
                        line_no = node.lineno
                        col_no = node.col_offset
                        snippet = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

                        finding = FindingData(
                            rule_id=self.rule_id,
                            title=self.name,
                            severity=self.severity,
                            language=self.language,
                            file_path=file_path,
                            line_number=line_no,
                            column_number=col_no,
                            end_line=getattr(node, 'end_lineno', line_no),
                            code_snippet=snippet,
                            message=f"Hardcoded sensitive secret detected in variable assignment '{var_name}'.",
                            confidence=self.confidence,
                            owasp_category=self.owasp_category,
                            recommendation=self.recommendation,
                            references=self.references
                        )
                        findings.append(finding)

        return findings
