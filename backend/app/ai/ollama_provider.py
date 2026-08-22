import json
import httpx
from typing import Dict, Any
from backend.app.ai.base import LLMProvider, AIExplanation
from backend.app.config import settings


class OllamaProvider(LLMProvider):
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL

    def is_available(self) -> bool:
        """Checks if local Ollama runtime is reachable."""
        try:
            url = f"{self.base_url}/api/version"
            response = httpx.get(url, timeout=2.0)
            return response.status_code == 200
        except Exception:
            return False

    def generate_explanation(
        self,
        rule_id: str,
        title: str,
        severity: str,
        code_snippet: str,
        file_path: str,
        line_number: int,
        rule_description: str,
        owasp_category: str,
        built_in_explanation: Dict[str, str]
    ) -> AIExplanation:
        """
        Attempts to generate an LLM explanation via Ollama.
        Falls back gracefully if Ollama service or model is unavailable.
        """
        if not self.is_available():
            return self._build_fallback(built_in_explanation)

        prompt = f"""You are an application security expert assisting a developer.
Analyze the following confirmed vulnerability detected by AST security rule '{rule_id}':

Vulnerability: {title} ({severity})
OWASP Category: {owasp_category}
File Location: {file_path} : Line {line_number}
Code Snippet:
```
{code_snippet}
```
Rule Description: {rule_description}

Provide a structured JSON response with exact keys:
"summary": brief overview of vulnerability
"root_cause": why this code is vulnerable
"why_dangerous": danger of this flaw
"potential_impact": potential impact if exploited
"recommended_fix": concrete fix advice
"secure_example": safe code example

RULES:
- Never invent vulnerabilities or files.
- Keep explanation accurate and concise.
- Output JSON ONLY.
"""

        try:
            url = f"{self.base_url}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }
            res = httpx.post(url, json=payload, timeout=8.0)
            if res.status_code == 200:
                data = res.json()
                raw_response = data.get("response", "")
                parsed = json.loads(raw_response)

                return AIExplanation(
                    summary=parsed.get("summary", built_in_explanation.get("summary", title)),
                    root_cause=parsed.get("root_cause", built_in_explanation.get("root_cause", rule_description)),
                    why_dangerous=parsed.get("why_dangerous", built_in_explanation.get("why_it_is_dangerous", "")),
                    potential_impact=parsed.get("potential_impact", built_in_explanation.get("potential_impact", "")),
                    recommended_fix=parsed.get("recommended_fix", built_in_explanation.get("recommended_fix", "")),
                    secure_example=parsed.get("secure_example", built_in_explanation.get("secure_example", "")),
                    provider_name="Ollama (Local LLM)",
                    model_name=self.model,
                    is_ai_generated=True
                )
        except Exception:
            pass  # Fall back to built-in explanation on any error or timeout

        return self._build_fallback(built_in_explanation)

    def _build_fallback(self, built_in: Dict[str, str]) -> AIExplanation:
        return AIExplanation(
            summary=built_in.get("summary", "Rule-Based Security Finding"),
            root_cause=built_in.get("root_cause", "AST rule pattern match detected."),
            why_dangerous=built_in.get("why_it_is_dangerous", "Unsanitized code violates security invariants."),
            potential_impact=built_in.get("potential_impact", "Security vulnerability in scanned file."),
            recommended_fix=built_in.get("recommended_fix", "Apply standard secure coding remediation."),
            secure_example=built_in.get("secure_example", "Use parameterized interfaces."),
            provider_name="Built-In Security Engine",
            model_name="Rule-Based (AI Offline)",
            is_ai_generated=False
        )
