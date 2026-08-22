import ast
from pathlib import Path
from backend.app.scanner.rules.python.sql_injection import PythonSQLInjectionRule
from backend.app.scanner.rules.python.command_injection import PythonCommandInjectionRule
from backend.app.scanner.rules.python.dangerous_eval import PythonDangerousEvalRule
from backend.app.scanner.rules.python.hardcoded_secret import PythonHardcodedSecretRule
from backend.app.scanner.rules.python.weak_crypto import PythonWeakCryptoRule
from backend.app.scanner.rules.python.unsafe_deserialization import PythonUnsafeDeserializationRule
from backend.app.scanner.rules.python.path_traversal import PythonPathTraversalRule


def _analyze_file(rule, file_path: Path):
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    return rule.analyze_python_ast(tree, str(file_path), source)


def test_sql_injection_rule():
    rule = PythonSQLInjectionRule()
    vuln_path = Path("examples/vulnerable/sql_injection.py")
    sec_path = Path("examples/secure/sql_injection_secure.py")

    vuln_findings = _analyze_file(rule, vuln_path)
    sec_findings = _analyze_file(rule, sec_path)

    assert len(vuln_findings) >= 2
    assert len(sec_findings) == 0


def test_command_injection_rule():
    rule = PythonCommandInjectionRule()
    vuln_path = Path("examples/vulnerable/command_injection.py")
    sec_path = Path("examples/secure/command_injection_secure.py")

    vuln_findings = _analyze_file(rule, vuln_path)
    sec_findings = _analyze_file(rule, sec_path)

    assert len(vuln_findings) >= 2
    assert len(sec_findings) == 0


def test_dangerous_eval_rule():
    rule = PythonDangerousEvalRule()
    vuln_path = Path("examples/vulnerable/dangerous_eval.py")

    vuln_findings = _analyze_file(rule, vuln_path)
    assert len(vuln_findings) >= 2


def test_hardcoded_secret_rule():
    rule = PythonHardcodedSecretRule()
    vuln_path = Path("examples/vulnerable/hardcoded_secret.py")
    sec_path = Path("examples/secure/safe_secrets_and_parsing.py")

    vuln_findings = _analyze_file(rule, vuln_path)
    sec_findings = _analyze_file(rule, sec_path)

    assert len(vuln_findings) >= 2
    assert len(sec_findings) == 0


def test_unsafe_deserialization_rule():
    rule = PythonUnsafeDeserializationRule()
    vuln_path = Path("examples/vulnerable/unsafe_deserialization.py")
    sec_path = Path("examples/secure/safe_secrets_and_parsing.py")

    vuln_findings = _analyze_file(rule, vuln_path)
    sec_findings = _analyze_file(rule, sec_path)

    assert len(vuln_findings) >= 2
    assert len(sec_findings) == 0
