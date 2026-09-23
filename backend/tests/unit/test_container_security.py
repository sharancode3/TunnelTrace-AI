"""Tests verifying container security boundaries and Docker Compose specifications."""

import re
from pathlib import Path


def test_dockerfile_security_boundaries():
    """Verify Dockerfile establishes unprivileged user (UID 10001) and security best practices."""
    dockerfile_path = Path(__file__).resolve().parent.parent.parent / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist in backend root"
    content = dockerfile_path.read_text(encoding="utf-8")

    # Verify unprivileged user creation and execution
    assert "useradd" in content
    assert "10001" in content
    assert "USER 10001:10001" in content or "USER appuser" in content

    # Verify no write bytecode and unbuffered python
    assert "PYTHONDONTWRITEBYTECODE=1" in content
    assert "PYTHONUNBUFFERED=1" in content

    # Verify non-root ownership of app and storage directories
    assert "chown -R 10001:10001" in content


def test_docker_compose_security_boundaries():
    """Verify docker-compose.yml drops capabilities, blocks root, and avoids Docker socket mounting."""
    compose_path = Path(__file__).resolve().parent.parent.parent.parent / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist in repository root"
    content = compose_path.read_text(encoding="utf-8")

    # Verify Docker socket is NEVER mounted
    assert "/var/run/docker.sock" not in content
    assert "docker.sock" not in content

    # Verify drop all capabilities
    assert "cap_drop:" in content
    assert "- ALL" in content

    # Verify no-new-privileges
    assert "no-new-privileges:true" in content

    # Verify unprivileged user 10001:10001 specified
    assert "10001:10001" in content

    # Verify internal loopback 127.0.0.1 bindings and no public 0.0.0.0 port exposures
    assert "127.0.0.1:" in content
    assert re.search(r"^\s*-\s*\"?0\.0\.0\.0:", content, re.MULTILINE) is None
