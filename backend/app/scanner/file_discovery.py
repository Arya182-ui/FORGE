import os
from pathlib import Path
from typing import List, Tuple, Set
from backend.app.config import settings


class FileDiscoveryError(Exception):
    """Exception raised when path validation or discovery fails."""
    pass


class FileDiscoveryService:
    def __init__(self, ignore_dirs: Set[str] = None, max_file_size: int = None):
        self.ignore_dirs = ignore_dirs or settings.DEFAULT_IGNORE_DIRS
        self.max_file_size = max_file_size or settings.MAX_FILE_SIZE_BYTES

    def validate_and_resolve_path(self, target_path_str: str) -> Path:
        """
        Validates target path existence and resolves absolute path.
        Prevents unauthorized path traversal outside safe system boundaries.
        """
        if not target_path_str or not target_path_str.strip():
            raise FileDiscoveryError("Target path cannot be empty.")

        path = Path(target_path_str).resolve()
        if not path.exists():
            raise FileDiscoveryError(f"Target path does not exist: '{target_path_str}'")

        return path

    def detect_language(self, file_path: Path) -> str:
        """Determines language based on file extension."""
        ext = file_path.suffix.lower()
        if ext == ".py":
            return "python"
        elif ext in [".js", ".jsx", ".ts", ".tsx"]:
            return "javascript"
        return "unknown"

    def discover_files(self, target_path_str: str, language_filter: str = None) -> List[Tuple[Path, str]]:
        """
        Discovers all valid source code files within the target path recursively.
        Returns list of (Path, language) tuples.
        """
        root_path = self.validate_and_resolve_path(target_path_str)
        discovered: List[Tuple[Path, str]] = []

        if root_path.is_file():
            lang = self.detect_language(root_path)
            if lang != "unknown" and (not language_filter or lang == language_filter.lower()):
                if root_path.stat().st_size <= self.max_file_size:
                    discovered.append((root_path, lang))
            return discovered

        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
            # Exclude ignored directories in-place
            dirnames[:] = [d for d in dirnames if d not in self.ignore_dirs and not d.startswith(".")]

            for filename in filenames:
                file_path = Path(dirpath) / filename

                # Extension check
                lang = self.detect_language(file_path)
                if lang == "unknown":
                    continue

                if language_filter and lang != language_filter.lower():
                    continue

                # File size check
                try:
                    st_size = file_path.stat().st_size
                    if st_size > self.max_file_size:
                        continue  # Skip files larger than maximum size limit
                except OSError:
                    continue

                discovered.append((file_path, lang))

                if len(discovered) >= settings.MAX_FILES_PER_SCAN:
                    break

        return discovered
