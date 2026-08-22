from typing import List, Any
from backend.app.scanner.rules.javascript.base import BaseJSRule
from backend.app.scanner.rules.base import FindingData


class JavaScriptPathTraversalRule(BaseJSRule):
    rule_id = "JS-PATH-001"
    name = "Potential Path Traversal in Node.js"
    description = "Passing user-controlled parameters directly into fs.readFile, fs.createReadStream, or res.sendFile permits unauthorized filesystem access."
    language = "javascript"
    severity = "HIGH"
    owasp_category = "A01:2021 Broken Access Control"
    confidence = 0.85
    recommendation = "Normalize paths using path.resolve() or path.join(), and verify the resolved path remains contained within the allowed base directory."
    references = [
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Path_Traversal_Cheat_Sheet.html"
    ]

    FILE_FUNCTIONS = {"readFile", "readFileSync", "createReadStream", "sendFile", "download"}

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        def visitor(node: Any):
            node_type = getattr(node, "type", None)
            if node_type == "CallExpression":
                callee = getattr(node, "callee", None)
                func_name = ""

                if callee and getattr(callee, "type", None) == "MemberExpression":
                    prop = getattr(callee, "property", None)
                    if prop and getattr(prop, "type", None) == "Identifier":
                        func_name = getattr(prop, "name", "")

                if func_name in self.FILE_FUNCTIONS:
                    arguments = getattr(node, "arguments", [])
                    if arguments:
                        first_arg = arguments[0]
                        arg_type = getattr(first_arg, "type", None)

                        # Flag dynamic non-literal parameters
                        if arg_type in {"Identifier", "BinaryExpression", "TemplateLiteral"}:
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
                                message=f"Potential Path Traversal: Dynamic path parameter passed to '{func_name}()' without containment checks.",
                                confidence=self.confidence,
                                owasp_category=self.owasp_category,
                                recommendation=self.recommendation,
                                references=self.references
                            )
                            findings.append(finding)

        self.walk_ast(tree, visitor)
        return findings
