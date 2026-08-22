import ast
from typing import List
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonWeakCryptoRule(BaseRule):
    rule_id = "PY-CRYPTO-001"
    name = "Weak Cryptography / Broken Hashing"
    description = "Use of legacy/broken cryptographic hash functions (MD5, SHA1) or weak pseudorandom number generators for sensitive cryptographic operations."
    language = "python"
    severity = "MEDIUM"
    owasp_category = "A02:2021 Cryptographic Failures"
    confidence = 0.90
    recommendation = "Use secure collision-resistant hash algorithms (SHA-256, SHA-3) or bcrypt/argon2 for password hashing, and the secrets module for secure random values."
    references = [
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://docs.python.org/3/library/secrets.html"
    ]

    WEAK_HASH_FUNCS = {"md5", "sha1"}

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            is_violation = False
            msg = ""

            # Check hashlib.md5 or hashlib.sha1
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr
                if module == "hashlib" and func in self.WEAK_HASH_FUNCS:
                    is_violation = True
                    msg = f"Use of broken cryptographic hash function 'hashlib.{func}()'."

            if is_violation:
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
                    message=msg,
                    confidence=self.confidence,
                    owasp_category=self.owasp_category,
                    recommendation=self.recommendation,
                    references=self.references
                )
                findings.append(finding)

        return findings
