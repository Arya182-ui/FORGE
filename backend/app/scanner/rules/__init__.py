from typing import List, Dict
from backend.app.scanner.rules.base import BaseRule
from backend.app.scanner.rules.python.sql_injection import PythonSQLInjectionRule
from backend.app.scanner.rules.python.command_injection import PythonCommandInjectionRule
from backend.app.scanner.rules.python.dangerous_eval import PythonDangerousEvalRule
from backend.app.scanner.rules.python.hardcoded_secret import PythonHardcodedSecretRule
from backend.app.scanner.rules.python.weak_crypto import PythonWeakCryptoRule
from backend.app.scanner.rules.python.unsafe_deserialization import PythonUnsafeDeserializationRule
from backend.app.scanner.rules.python.path_traversal import PythonPathTraversalRule

from backend.app.scanner.rules.javascript.sql_injection import JavaScriptSQLInjectionRule
from backend.app.scanner.rules.javascript.command_injection import JavaScriptCommandInjectionRule
from backend.app.scanner.rules.javascript.dangerous_eval import JavaScriptDangerousEvalRule
from backend.app.scanner.rules.javascript.xss import JavaScriptXSSRule
from backend.app.scanner.rules.javascript.hardcoded_secret import JavaScriptHardcodedSecretRule
from backend.app.scanner.rules.javascript.path_traversal import JavaScriptPathTraversalRule

PYTHON_RULES: List[BaseRule] = [
    PythonSQLInjectionRule(),
    PythonCommandInjectionRule(),
    PythonDangerousEvalRule(),
    PythonHardcodedSecretRule(),
    PythonWeakCryptoRule(),
    PythonUnsafeDeserializationRule(),
    PythonPathTraversalRule(),
]

JAVASCRIPT_RULES: List[BaseRule] = [
    JavaScriptSQLInjectionRule(),
    JavaScriptCommandInjectionRule(),
    JavaScriptDangerousEvalRule(),
    JavaScriptXSSRule(),
    JavaScriptHardcodedSecretRule(),
    JavaScriptPathTraversalRule(),
]

ALL_RULES: Dict[str, List[BaseRule]] = {
    "python": PYTHON_RULES,
    "javascript": JAVASCRIPT_RULES,
}

def get_rules_for_language(language: str) -> List[BaseRule]:
    return ALL_RULES.get(language.lower(), [])

def get_all_registered_rules() -> List[BaseRule]:
    rules = []
    for lang_rules in ALL_RULES.values():
        rules.extend(lang_rules)
    return rules
