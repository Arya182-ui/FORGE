from backend.app.ai.base import LLMProvider
from backend.app.ai.ollama_provider import OllamaProvider
from backend.app.config import settings


def get_llm_provider() -> LLMProvider:
    """
    Factory function returning active LLM provider based on settings.
    Defaults to OllamaProvider.
    """
    provider_type = settings.LLM_PROVIDER.lower()
    if provider_type == "ollama":
        return OllamaProvider()
    
    # Default fallback
    return OllamaProvider()
