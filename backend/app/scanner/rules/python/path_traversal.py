import ast
from typing import List
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonPathTraversalRule(BaseRule):
    rule_id = "PY-PATH-001"
    name = "Potential Path Traversal"
    description = "Opening files or serving paths directly constructed from user parameters without path normalization and containment validation allows unauthorized file access."
    language = "python"
    severity = "HIGH"
    owasp_category = "A01:2021 Broken Access Control"
    confidence = 0.85
    recommendation = "Validate and sanitize requested file paths using os.path.abspath or Path.resolve(), and verify the resolved path stays within an allowed base directory."
    references = [
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Path_Traversal_Cheat_Sheet.html"
    ]

    FILE_FUNCS = {"open", "send_file", "FileResponse", "read_file"}

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in self.FILE_FUNCS:
                if not node.args:
                    continue

                first_arg = node.args[0]
                # If first arg is variable (ast.Name) or formatted string (ast.JoinedStr) or string binop
                is_dynamic = isinstance(first_arg, (ast.Name, ast.JoinedStr, ast.BinOp))

                if is_dynamic:
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
                        message=f"Potential Path Traversal: Dynamic file path parameter supplied to '{func_name}()' without containment checks.",
                        confidence=self.confidence,
                        owasp_category=self.owasp_category,
                        recommendation=self.recommendation,
                        references=self.references
                    )
                    findings.append(finding)

        return findings
