import ast
from typing import List
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonCommandInjectionRule(BaseRule):
    rule_id = "PY-CMD-001"
    name = "Command Injection / Dangerous Subprocess"
    description = "Executing OS commands via os.system, os.popen, or subprocess with shell=True can allow remote command execution if input is not strictly validated."
    language = "python"
    severity = "CRITICAL"
    owasp_category = "A03:2021 Injection"
    confidence = 0.95
    recommendation = "Avoid shell=True in subprocess calls. Pass arguments as a list of strings directly to the executable (e.g. subprocess.run(['ls', path], shell=False))."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://docs.python.org/3/library/subprocess.html#security-considerations"
    ]

    DANGEROUS_OS_FUNCS = {"system", "popen", "execv", "execve", "spawnl", "spawnle"}

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            is_violation = False
            msg = ""

            # Check os.system / os.popen
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr
                if module == "os" and func in self.DANGEROUS_OS_FUNCS:
                    is_violation = True
                    msg = f"Use of dangerous OS command execution function 'os.{func}'."

            # Check subprocess.* with shell=True
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr
                if module == "subprocess":
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                is_violation = True
                                msg = f"subprocess.{func}() call with shell=True allows command injection."

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
