"""Unit tests for the local file storage abstraction and path security."""

import pytest

from app.core.errors import PathTraversalError
from app.services.storage.local import LocalStorageProvider


def test_storage_initialization_and_directories(temp_storage_dir: str):
    """Test storage provider initialization creates standard subdirectories."""
    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    assert storage.root_path.exists()
    assert (storage.root_path / "captures").exists()
    assert (storage.root_path / "live").exists()
    assert (storage.root_path / "reports").exists()
    assert (storage.root_path / "tmp").exists()


def test_path_traversal_rejection(temp_storage_dir: str):
    """Ensure path traversal attacks with '..' or absolute paths outside root are blocked."""
    storage = LocalStorageProvider(root_dir=temp_storage_dir)

    malicious_paths = [
        "../secret.txt",
        "../../etc/passwd",
        "captures/../../etc/shadow",
        "..\\windows\\system32",
        "captures/..\\..\\boot.ini",
    ]

    for bad_path in malicious_paths:
        with pytest.raises(PathTraversalError):
            storage.resolve_safe_path(bad_path)


def test_storage_write_read_delete(temp_storage_dir: str):
    """Test atomic file writing, reading, and deletion within local storage."""
    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/test_pcap_meta.json"
    content = b'{"capture_id": "test-123", "status": "valid"}'

    # Write
    written_path = storage.write_file(rel_path, content)
    assert written_path.exists()
    assert storage.exists(rel_path)

    # Read
    read_data = storage.read_file(rel_path)
    assert read_data == content

    # Delete
    deleted = storage.delete_file(rel_path)
    assert deleted is True
    assert not storage.exists(rel_path)

    # Delete non-existent
    assert storage.delete_file("captures/non_existent.pcap") is False


def test_storage_writability_probe(temp_storage_dir: str):
    """Verify that storage writability probe test succeeds on healthy directory."""
    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    assert storage.check_writability() is True
