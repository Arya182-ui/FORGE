from typing import List, Any
from backend.app.scanner.rules.javascript.base import BaseJSRule
from backend.app.scanner.rules.base import FindingData


class JavaScriptCommandInjectionRule(BaseJSRule):
    rule_id = "JS-CMD-001"
    name = "Command Injection / Dangerous Child Process"
    description = "Invoking child_process.exec, execSync, or spawn with shell: true runs input directly inside a system shell, permitting remote command execution."
    language = "javascript"
    severity = "CRITICAL"
    owasp_category = "A03:2021 Injection"
    confidence = 0.95
    recommendation = "Use execFile or spawn without shell: true. Pass arguments as a sanitized array of strings rather than a concatenated command string."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback"
    ]

    DANGEROUS_EXEC_FUNCS = {"exec", "execSync"}

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        def visitor(node: Any):
            node_type = getattr(node, "type", None)
            if node_type == "CallExpression":
                callee = getattr(node, "callee", None)
                func_name = ""

                if callee:
                    if getattr(callee, "type", None) == "Identifier":
                        func_name = getattr(callee, "name", "")
                    elif getattr(callee, "type", None) == "MemberExpression":
                        prop = getattr(callee, "property", None)
                        if prop and getattr(prop, "type", None) == "Identifier":
                            func_name = getattr(prop, "name", "")

                is_violation = False
                msg = ""

                if func_name in self.DANGEROUS_EXEC_FUNCS:
                    is_violation = True
                    msg = f"Use of dangerous child_process function '{func_name}()'."
                elif func_name in {"spawn", "spawnSync"}:
                    arguments = getattr(node, "arguments", [])
                    # Check options object for shell: true
                    for arg in arguments:
                        if getattr(arg, "type", None) == "ObjectExpression":
                            for prop in getattr(arg, "properties", []):
                                key = getattr(prop, "key", None)
                                val = getattr(prop, "value", None)
                                key_name = getattr(key, "name", "") or getattr(key, "value", "")
                                if key_name == "shell" and getattr(val, "value", None) is True:
                                    is_violation = True
                                    msg = f"{func_name}() invoked with shell: true."

                if is_violation:
                    loc = getattr(node, "loc", None)
                    line_no = loc.start.line if loc else 1
                    col_no = loc.start.column if loc else 0
                    snippet = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

                    finding = FindingData(
                        rule_id=self.rule_id,
                        title=self.name,
                        severity=self.severity,
                        language=self.language,
                        file_path=file_path,
                        line_number=line_no,
                        column_number=col_no,
                        end_line=loc.end.line if loc else line_no,
                        code_snippet=snippet,
                        message=msg,
                        confidence=self.confidence,
                        owasp_category=self.owasp_category,
                        recommendation=self.recommendation,
                        references=self.references
                    )
                    findings.append(finding)

        self.walk_ast(tree, visitor)
        return findings
