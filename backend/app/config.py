import os
from typing import List, Set, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict



class Settings(BaseSettings):
    PROJECT_NAME: str = "FORGE AI Code Review & Security Platform"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"

    # Database
    DATABASE_URL: str = "sqlite:///./forge.db"

    # Scanner Settings
    MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB limit
    MAX_FILES_PER_SCAN: int = 5000
    DEFAULT_IGNORE_DIRS: Set[str] = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        "coverage",
        ".cache",
        ".idea",
        ".vscode",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "site-packages",
    }
    SUPPORTED_EXTENSIONS: Set[str] = {".py", ".js", ".jsx", ".ts", ".tsx"}

    # AI Integration Settings (Optional)
    LLM_PROVIDER: str = "ollama"  # "ollama" or "disabled" or optional external
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "codellama"
    AI_ENABLED: bool = False  # Strict default: scanner works 100% without AI

    # GitHub Integration Settings
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: str = "forge_secret_key_2026"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )



settings = Settings()
