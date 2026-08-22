import ast
from typing import List
from backend.app.scanner.rules.base import BaseRule, FindingData


class PythonUnsafeDeserializationRule(BaseRule):
    rule_id = "PY-DESER-001"
    name = "Unsafe Object Deserialization"
    description = "Deserializing untrusted data with pickle or un-sanitized yaml.load can allow arbitrary code execution when dangerous objects are reconstructed."
    language = "python"
    severity = "HIGH"
    owasp_category = "A08:2021 Software and Data Integrity Failures"
    confidence = 0.95
    recommendation = "Use safe serialization formats like JSON, or yaml.safe_load() instead of pickle or unsafe PyYAML loaders."
    references = [
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://docs.python.org/3/library/pickle.html#restricted-execution"
    ]

    def analyze_python_ast(self, tree: ast.AST, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            is_violation = False
            msg = ""

            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr

                # Check pickle.loads / pickle.load
                if module in {"pickle", "_pickle", "cPickle"} and func in {"load", "loads"}:
                    is_violation = True
                    msg = f"Use of unsafe deserialization function '{module}.{func}()'."

                # Check yaml.load without Loader=SafeLoader or yaml.unsafe_load
                elif module in {"yaml", "ruamel.yaml"}:
                    if func == "unsafe_load":
                        is_violation = True
                        msg = f"Use of unsafe YAML deserialization function '{module}.unsafe_load()'."
                    elif func == "load":
                        # Check if Loader keyword argument is present and is SafeLoader
                        loader_present = False
                        for kw in node.keywords:
                            if kw.arg == "Loader":
                                loader_present = True
                                if isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr:
                                    pass  # SafeLoader used
                                elif isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                                    pass  # SafeLoader used
                                else:
                                    is_violation = True
                                    msg = f"yaml.load() used with non-safe Loader."

                        if not loader_present:
                            is_violation = True
                            msg = f"yaml.load() used without explicit Loader parameter (defaults to unsafe in legacy PyYAML)."

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
