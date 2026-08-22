import ast
from typing import List
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonDangerousEvalRule(BaseRule):
    rule_id = "PY-EVAL-001"
    name = "Dangerous Code Execution (eval / exec)"
    description = "Dynamic code evaluation using eval() or exec() executes arbitrary code strings at runtime, leading to complete remote code execution."
    language = "python"
    severity = "CRITICAL"
    owasp_category = "A03:2021 Injection"
    confidence = 0.98
    recommendation = "Replace eval/exec with safe alternatives such as ast.literal_eval for parsing primitives, or structured JSON parsing."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://docs.python.org/3/library/ast.html#ast.literal_eval"
    ]

    DANGEROUS_FUNCTIONS = {"eval", "exec"}

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name in self.DANGEROUS_FUNCTIONS:
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
                    message=f"Use of dangerous dynamic execution function '{func_name}()'.",
                    confidence=self.confidence,
                    owasp_category=self.owasp_category,
                    recommendation=self.recommendation,
                    references=self.references
                )
                findings.append(finding)

        return findings
