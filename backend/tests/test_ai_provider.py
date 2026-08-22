from backend.app.ai.ollama_provider import OllamaProvider
from backend.app.ai.factory import get_llm_provider


def test_ollama_provider_fallback_when_offline():
    # Configure unreachable host
    provider = OllamaProvider(base_url="http://localhost:59999", model="nonexistent-model")
    assert provider.is_available() is False

    built_in = {
        "summary": "Potential SQL Injection",
        "root_cause": "Dynamic query string concatenation",
        "why_it_is_dangerous": "Attacker can execute arbitrary SQL statements",
        "potential_impact": "Data breach",
        "recommended_fix": "Use parameterized queries",
        "secure_example": "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"
    }

    explanation = provider.generate_explanation(
        rule_id="PY-SQL-001",
        title="Potential SQL Injection",
        severity="HIGH",
        code_snippet="cursor.execute(query)",
        file_path="app.py",
        line_number=10,
        rule_description="Dynamic SQL string",
        owasp_category="A03:2021 Injection",
        built_in_explanation=built_in
    )

    assert explanation.is_ai_generated is False
    assert explanation.provider_name == "Built-In Security Engine"
    assert explanation.summary == "Potential SQL Injection"
    assert explanation.recommended_fix == "Use parameterized queries"


def test_ai_factory():
    provider = get_llm_provider()
    assert isinstance(provider, OllamaProvider)
