import ast
from typing import List, Dict
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonSQLInjectionRule(BaseRule):
    rule_id = "PY-SQL-001"
    name = "Potential SQL Injection"
    description = "User-controlled input or formatted string is directly concatenated into a SQL statement, allowing query structure manipulation."
    language = "python"
    severity = "HIGH"
    owasp_category = "A03:2021 Injection"
    confidence = 0.90
    recommendation = "Use parameterized queries or ORM binding (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ]

    EXECUTE_METHODS = {"execute", "executemany", "raw", "text", "query"}

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        # F-strings (JoinedStr)
        if isinstance(node, ast.JoinedStr):
            return True

        # String binary operations (+ concatenation or % formatting)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True

        # .format() call on string
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return True

        return False

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        # Map variable assignments in scope: var_name -> ast_node (assignment value)
        var_assignments: Dict[str, ast.AST] = {}

        # First pass: collect variable assignments
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_assignments[target.id] = node.value

        # Second pass: check execute calls
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            method_name = ""
            if isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                method_name = node.func.id

            if method_name in self.EXECUTE_METHODS:
                if not node.args:
                    continue

                first_arg = node.args[0]
                target_node = first_arg

                # If passed a variable name, look up its assignment
                if isinstance(first_arg, ast.Name) and first_arg.id in var_assignments:
                    target_node = var_assignments[first_arg.id]

                if self._is_dynamic_string(target_node):
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
                        message="Potential SQL injection detected: Dynamic string formatting used in SQL query execution call.",
                        confidence=self.confidence,
                        owasp_category=self.owasp_category,
                        recommendation=self.recommendation,
                        references=self.references
                    )
                    findings.append(finding)

        return findings
