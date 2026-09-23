# ruff: noqa: E402
import shutil
import sys
import tempfile
from collections.abc import Generator
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = Path(__file__).resolve().parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.services.storage.local import LocalStorageProvider


@pytest.fixture(scope="session")
def temp_storage_dir() -> Generator[str, None, None]:
    """Provide an isolated temporary directory for file storage during testing."""
    tmp = tempfile.mkdtemp(prefix="tt_test_storage_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def test_settings(temp_storage_dir: str) -> Settings:
    """Provide isolated settings for testing."""
    return Settings(
        app_name="TunnelTrace AI Test",
        app_env="testing",
        app_debug=True,
        app_log_level="DEBUG",
        database_url="postgresql+asyncpg://postgres:postgres@localhost:5432/tunneltrace_test",
        redis_url="redis://localhost:6379/1",
        storage_root=temp_storage_dir,
        cors_allowed_origins=["http://localhost:3000"],
        netagent_enabled=False,
    )


@pytest.fixture
def app(test_settings: Settings):
    """FastAPI application instance configured for testing."""
    app_instance = create_app(settings=test_settings)
    return app_instance


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """Synchronous test client for API endpoint testing."""
    with TestClient(app=app, base_url="http://testserver") as test_client:
        yield test_client


@pytest.fixture
def local_storage(temp_storage_dir: str) -> LocalStorageProvider:
    """Instantiated local storage provider with clean temporary root."""
    return LocalStorageProvider(root_dir=temp_storage_dir)
