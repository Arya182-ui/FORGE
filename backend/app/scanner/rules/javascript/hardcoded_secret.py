import re
from typing import List, Any
from backend.app.scanner.rules.javascript.base import BaseJSRule
from backend.app.scanner.rules.base import FindingData


class JavaScriptHardcodedSecretRule(BaseJSRule):
    rule_id = "JS-SEC-001"
    name = "Hardcoded Sensitive Secret in JavaScript"
    description = "Hardcoding credentials, secret tokens, or API keys in JavaScript code exposes secrets in source repositories or client-side bundles."
    language = "javascript"
    severity = "HIGH"
    owasp_category = "A07:2021 Identification and Authentication Failures"
    confidence = 0.85
    recommendation = "Inject sensitive configuration securely via environment variables (e.g. process.env.SECRET_KEY)."
    references = [
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    ]

    SECRET_KEYWORDS = re.compile(
        r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|jwt[_-]?secret)",
        re.IGNORECASE
    )

    IGNORE_VALUES = {"todo", "change_me", "placeholder", "your_secret_here", "none", "", "test", "username", "admin"}

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        def visitor(node: Any):
            node_type = getattr(node, "type", None)
            var_name = ""
            val_str = ""

            if node_type == "VariableDeclarator":
                id_node = getattr(node, "id", None)
                init_node = getattr(node, "init", None)
                if id_node and getattr(id_node, "type", None) == "Identifier":
                    var_name = getattr(id_node, "name", "")
                if init_node and getattr(init_node, "type", None) == "Literal" and isinstance(getattr(init_node, "value", None), str):
                    val_str = getattr(init_node, "value", "")

            elif node_type == "Property":
                key_node = getattr(node, "key", None)
                val_node = getattr(node, "value", None)
                if key_node:
                    var_name = getattr(key_node, "name", "") or getattr(key_node, "value", "")
                if val_node and getattr(val_node, "type", None) == "Literal" and isinstance(getattr(val_node, "value", None), str):
                    val_str = getattr(val_node, "value", "")

            if var_name and val_str:
                if self.SECRET_KEYWORDS.search(var_name):
                    clean_val = val_str.strip().lower()
                    if clean_val not in self.IGNORE_VALUES and len(val_str) >= 6:
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
                            message=f"Hardcoded secret detected in JavaScript variable assignment '{var_name}'.",
                            confidence=self.confidence,
                            owasp_category=self.owasp_category,
                            recommendation=self.recommendation,
                            references=self.references
                        )
                        findings.append(finding)

        self.walk_ast(tree, visitor)
        return findings
