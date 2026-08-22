import pytest
from pathlib import Path
from backend.app.scanner.parsers.javascript_ast import JavaScriptASTParser
from backend.app.scanner.rules.javascript.sql_injection import JavaScriptSQLInjectionRule
from backend.app.scanner.rules.javascript.command_injection import JavaScriptCommandInjectionRule
from backend.app.scanner.rules.javascript.dangerous_eval import JavaScriptDangerousEvalRule
from backend.app.scanner.rules.javascript.xss import JavaScriptXSSRule
from backend.app.scanner.rules.javascript.hardcoded_secret import JavaScriptHardcodedSecretRule
from backend.app.scanner.rules.javascript.path_traversal import JavaScriptPathTraversalRule
from backend.app.scanner.engine import ScannerEngine


def _analyze_js_file(rule, file_path: Path):
    tree, source, lines, err = JavaScriptASTParser.parse_file(file_path)
    assert err is None, f"Failed to parse {file_path.name}: {err}"
    return rule.analyze_javascript_ast(tree, str(file_path), source)


def test_js_sql_injection_rule():
    rule = JavaScriptSQLInjectionRule()
    vuln_path = Path("examples/vulnerable/js_vulnerable.js")
    sec_path = Path("examples/secure/js_secure.js")

    vuln_findings = _analyze_js_file(rule, vuln_path)
    sec_findings = _analyze_js_file(rule, sec_path)

    assert len(vuln_findings) >= 1
    assert len(sec_findings) == 0


def test_js_command_injection_rule():
    rule = JavaScriptCommandInjectionRule()
    vuln_path = Path("examples/vulnerable/js_vulnerable.js")
    sec_path = Path("examples/secure/js_secure.js")

    vuln_findings = _analyze_js_file(rule, vuln_path)
    sec_findings = _analyze_js_file(rule, sec_path)

    assert len(vuln_findings) >= 1
    assert len(sec_findings) == 0


def test_js_dangerous_eval_rule():
    rule = JavaScriptDangerousEvalRule()
    vuln_path = Path("examples/vulnerable/js_vulnerable.js")

    vuln_findings = _analyze_js_file(rule, vuln_path)
    assert len(vuln_findings) >= 1


def test_js_xss_rule():
    rule = JavaScriptXSSRule()
    vuln_path = Path("examples/vulnerable/js_vulnerable.js")
    sec_path = Path("examples/secure/js_secure.js")

    vuln_findings = _analyze_js_file(rule, vuln_path)
    sec_findings = _analyze_js_file(rule, sec_path)

    assert len(vuln_findings) >= 1
    assert len(sec_findings) == 0


def test_js_hardcoded_secret_rule():
    rule = JavaScriptHardcodedSecretRule()
    vuln_path = Path("examples/vulnerable/js_vulnerable.js")
    sec_path = Path("examples/secure/js_secure.js")

    vuln_findings = _analyze_js_file(rule, vuln_path)
    sec_findings = _analyze_js_file(rule, sec_path)

    assert len(vuln_findings) >= 2
    assert len(sec_findings) == 0


def test_js_path_traversal_rule():
    rule = JavaScriptPathTraversalRule()
    vuln_path = Path("examples/vulnerable/js_vulnerable.js")

    vuln_findings = _analyze_js_file(rule, vuln_path)
    assert len(vuln_findings) >= 1


def test_scanner_engine_javascript_scan():
    engine = ScannerEngine()
    report = engine.run_scan("examples/vulnerable", language_filter="javascript", save_to_db=False)

    summary = report.summary
    assert summary.total_findings_count >= 6
    assert summary.scanned_files_count >= 1

    rule_ids = {f.rule_id for f in report.findings}
    assert "JS-SQL-001" in rule_ids
    assert "JS-CMD-001" in rule_ids
    assert "JS-EVAL-001" in rule_ids
    assert "JS-XSS-001" in rule_ids
    assert "JS-SEC-001" in rule_ids
    assert "JS-PATH-001" in rule_ids
