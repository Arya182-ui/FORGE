from typing import List, Any
from backend.app.scanner.rules.javascript.base import BaseJSRule
from backend.app.scanner.rules.base import FindingData


class JavaScriptDangerousEvalRule(BaseJSRule):
    rule_id = "JS-EVAL-001"
    name = "Dangerous Dynamic Code Execution (eval / Function)"
    description = "Dynamic code evaluation via eval(), Function constructor, or string-based setTimeout/setInterval executes arbitrary JavaScript strings."
    language = "javascript"
    severity = "CRITICAL"
    owasp_category = "A03:2021 Injection"
    confidence = 0.98
    recommendation = "Avoid eval() and Function constructor. Pass named functions or arrow function callbacks to setTimeout/setInterval instead of string codes."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"
    ]

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        def visitor(node: Any):
            node_type = getattr(node, "type", None)
            is_violation = False
            msg = ""

            # Check eval() call or setTimeout/setInterval with string arg
            if node_type == "CallExpression":
                callee = getattr(node, "callee", None)
                func_name = ""
                if callee and getattr(callee, "type", None) == "Identifier":
                    func_name = getattr(callee, "name", "")

                if func_name == "eval":
                    is_violation = True
                    msg = "Use of dangerous dynamic code execution function 'eval()'."
                elif func_name in {"setTimeout", "setInterval"}:
                    arguments = getattr(node, "arguments", [])
                    if arguments:
                        first_arg_type = getattr(arguments[0], "type", None)
                        if first_arg_type in {"Literal", "BinaryExpression", "TemplateLiteral"}:
                            is_violation = True
                            msg = f"Use of string parameter in '{func_name}()' evaluates code dynamically."

            # Check new Function(...)
            elif node_type == "NewExpression":
                callee = getattr(node, "callee", None)
                if callee and getattr(callee, "type", None) == "Identifier":
                    if getattr(callee, "name", "") == "Function":
                        is_violation = True
                        msg = "Use of 'new Function()' constructor executes dynamic code strings."

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
