import pytest
from pathlib import Path
from backend.app.scanner.file_discovery import FileDiscoveryService, FileDiscoveryError


def test_file_discovery_valid_path(tmp_path):
    # Create test directory structure
    py_file = tmp_path / "app.py"
    py_file.write_text("print('hello')")

    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "ignored.py").write_text("print('ignored')")

    service = FileDiscoveryService()
    files = service.discover_files(str(tmp_path))

    file_names = [f[0].name for f in files]
    assert "app.py" in file_names
    assert "ignored.py" not in file_names


def test_file_discovery_invalid_path():
    service = FileDiscoveryService()
    with pytest.raises(FileDiscoveryError):
        service.discover_files("non_existent_directory_12345")


def test_language_detection():
    service = FileDiscoveryService()
    assert service.detect_language(Path("test.py")) == "python"
    assert service.detect_language(Path("test.js")) == "javascript"
    assert service.detect_language(Path("test.txt")) == "unknown"
