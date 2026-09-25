"""Authentication and scope authorization guard for Continuous Monitoring telemetry sensors."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.monitoring import MonitoredGateway, MonitoredSensor


class SensorAuthenticationError(HTTPException):
    """Raised when sensor credential validation fails."""

    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=status_code, detail=detail)


class ScopeAuthorizationError(HTTPException):
    """Raised when an authenticated sensor attempts cross-scope or cross-gateway ingestion."""

    def __init__(self, detail: str, status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(status_code=status_code, detail=detail)


def generate_sensor_token() -> tuple[str, str, str]:
    """Generates a secure random sensor credential, returning (raw_token, token_hash, token_prefix).
    
    The raw_token is displayed once to the operator and NEVER persisted or logged in plaintext.
    """
    raw_token = f"tt_sn_{secrets.token_urlsafe(32)}"
    token_hash = hash_token(raw_token)
    token_prefix = f"{raw_token[:12]}..."
    return raw_token, token_hash, token_prefix


def hash_token(raw_token: str) -> str:
    """Computes SHA-256 digest of a sensor authentication token."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def is_local_client(client_host: str | None) -> bool:
    """Determines if the requesting client is on localhost/loopback."""
    if not client_host:
        return False
    try:
        ip = ipaddress.ip_address(client_host)
        return ip.is_loopback
    except ValueError:
        return client_host in ("127.0.0.1", "localhost", "::1", "testclient")


async def verify_sensor_credential(
    db: AsyncSession,
    raw_token: str | None,
    client_host: str | None = None,
) -> MonitoredSensor | None:
    """Authenticates the incoming sensor request via X-Sensor-Token header.
    
    Enforces constant-time hash comparison, status check (ACTIVE vs REVOKED/DISABLED),
    and strictly fails closed unless running in explicit local dev mode.
    """
    if raw_token and raw_token.strip():
        token_hash = hash_token(raw_token)
        query = select(MonitoredSensor).where(MonitoredSensor.auth_token_hash == token_hash)
        res = await db.execute(query)
        sensor = res.scalar_one_or_none()

        if not sensor:
            raise SensorAuthenticationError("Invalid sensor authentication credential.")

        # Constant-time comparison
        if not hmac.compare_digest(sensor.auth_token_hash, token_hash):
            raise SensorAuthenticationError("Invalid sensor authentication credential.")

        # Check status
        if sensor.status == "REVOKED":
            raise SensorAuthenticationError(
                f"Sensor '{sensor.sensor_name}' credential has been revoked.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if sensor.status == "DISABLED":
            raise SensorAuthenticationError(
                f"Sensor '{sensor.sensor_name}' is administratively disabled.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        return sensor

    # Fallback to local dev check if no token provided
    if settings.MONITORING_ALLOW_UNAUTHENTICATED_LOCAL and is_local_client(client_host):
        return None

    raise SensorAuthenticationError(
        "Missing X-Sensor-Token header. Authenticated sensor identity is required for telemetry ingestion.",
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


def validate_sensor_event_scope(
    sensor: MonitoredSensor | None,
    gateway_id: uuid.UUID,
    authorized_scope: str,
) -> None:
    """Strictly validates that an authenticated sensor ingests data only for its bound gateway and scope."""
    if sensor is None:
        # In unauthenticated local mode, no binding to compare against
        return

    if sensor.gateway_id != gateway_id:
        raise ScopeAuthorizationError(
            f"Cross-gateway authorization violation: Sensor '{sensor.sensor_name}' is bound to "
            f"gateway '{sensor.gateway_id}', but attempted to ingest event for gateway '{gateway_id}'."
        )

    if sensor.authorized_scope.strip() != authorized_scope.strip():
        raise ScopeAuthorizationError(
            f"Cross-scope authorization violation: Sensor '{sensor.sensor_name}' is bound to "
            f"scope '{sensor.authorized_scope}', but attempted to ingest event with scope '{authorized_scope}'."
        )
