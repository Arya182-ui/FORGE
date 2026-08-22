from typing import List, Any
from backend.app.scanner.rules.javascript.base import BaseJSRule
from backend.app.scanner.rules.base import FindingData


class JavaScriptSQLInjectionRule(BaseJSRule):
    rule_id = "JS-SQL-001"
    name = "Potential JavaScript / Node.js SQL Injection"
    description = "Concatenating or interpolating user variables into raw SQL query functions in Node.js (db.query, sequelize.query, knex.raw) allows SQL Injection."
    language = "javascript"
    severity = "HIGH"
    owasp_category = "A03:2021 Injection"
    confidence = 0.90
    recommendation = "Use parameterized SQL queries with placeholder arrays (e.g., db.query('SELECT * FROM users WHERE id = ?', [userId]))."
    references = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html"
    ]

    QUERY_METHODS = {"query", "raw", "execute"}

    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        findings: List[FindingData] = []
        lines = source_code.splitlines()

        def visitor(node: Any):
            node_type = getattr(node, "type", None)
            if node_type == "CallExpression":
                callee = getattr(node, "callee", None)
                method_name = ""

                if callee and getattr(callee, "type", None) == "MemberExpression":
                    property_node = getattr(callee, "property", None)
                    if property_node and getattr(property_node, "type", None) == "Identifier":
                        method_name = getattr(property_node, "name", "")

                if method_name in self.QUERY_METHODS:
                    arguments = getattr(node, "arguments", [])
                    if arguments:
                        first_arg = arguments[0]
                        arg_type = getattr(first_arg, "type", None)

                        is_dynamic = False
                        if arg_type == "BinaryExpression" and getattr(first_arg, "operator", "") == "+":
                            is_dynamic = True
                        elif arg_type == "TemplateLiteral":
                            expressions = getattr(first_arg, "expressions", [])
                            if expressions:
                                is_dynamic = True

                        if is_dynamic:
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
                                message="Potential Node.js SQL Injection: Dynamic string concatenation or template literal passed to SQL query function.",
                                confidence=self.confidence,
                                owasp_category=self.owasp_category,
                                recommendation=self.recommendation,
                                references=self.references
                            )
                            findings.append(finding)

        self.walk_ast(tree, visitor)
        return findings
