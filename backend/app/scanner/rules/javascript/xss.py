from typing import List, Any
from backend.app.scanner.rules.javascript.base import BaseJSRule
from backend.app.scanner.rules.base import FindingData


class JavaScriptXSSRule(BaseJSRule):
    rule_id = "JS-XSS-001"
    name = "Cross-Site Scripting (DOM XSS / Unsafe Sink)"
    description = "Writing unsanitized dynamic markup into DOM sinks (innerHTML, outerHTML, document.write, dangerouslySetInnerHTML) causes DOM-based Cross-Site Scripting."
    language = "javascript"
    severity = "HIGH"
    owasp_category = "A03:2021 Injection"
    confidence = 0.90
    recommendation = "Use safe text assignment properties like textContent or innerText, or sanitize HTML using DOMPurify before DOM insertion."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
    ]

    DANGEROUS_PROPERTIES = {"innerHTML", "outerHTML"}

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        def visitor(node: Any):
            node_type = getattr(node, "type", None)
            is_violation = False
            msg = ""

            # Check AssignmentExpression to innerHTML or outerHTML
            if node_type == "AssignmentExpression":
                left = getattr(node, "left", None)
                if left and getattr(left, "type", None) == "MemberExpression":
                    prop = getattr(left, "property", None)
                    prop_name = getattr(prop, "name", "") if prop else ""
                    if prop_name in self.DANGEROUS_PROPERTIES:
                        is_violation = True
                        msg = f"Unsafe assignment to DOM sink '{prop_name}' allows DOM-based XSS."

            # Check document.write() call
            elif node_type == "CallExpression":
                callee = getattr(node, "callee", None)
                if callee and getattr(callee, "type", None) == "MemberExpression":
                    obj = getattr(callee, "object", None)
                    prop = getattr(callee, "property", None)
                    if obj and prop:
                        obj_name = getattr(obj, "name", "")
                        prop_name = getattr(prop, "name", "")
                        if obj_name == "document" and prop_name in {"write", "writeln"}:
                            is_violation = True
                            msg = f"Use of unsafe DOM sink 'document.{prop_name}()'."

            # Check React dangerouslySetInnerHTML property
            elif node_type == "Property":
                key = getattr(node, "key", None)
                key_name = getattr(key, "name", "") or getattr(key, "value", "")
                if key_name == "dangerouslySetInnerHTML":
                    is_violation = True
                    msg = "Use of React 'dangerouslySetInnerHTML' can introduce XSS if input is untrusted."

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
