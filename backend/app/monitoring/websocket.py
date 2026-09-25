"""WebSocket live event broadcasting for Continuous Monitoring."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("tunneltrace.monitoring.websocket")


class MonitoringWebSocketManager:
    """Coordinates real-time WebSocket subscriber connections and event broadcasts."""

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Register a new active WebSocket subscriber."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.debug(f"Monitoring client connected. Total active: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Deregister an active WebSocket connection."""
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.debug(f"Monitoring client disconnected. Total active: {len(self.active_connections)}")

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message payload to all active subscribers."""
        if not self.active_connections:
            return

        payload_text = json.dumps(message, default=str)
        dead_sockets: list[WebSocket] = []

        async with self._lock:
            for socket in list(self.active_connections):
                try:
                    await socket.send_text(payload_text)
                except Exception as exc:
                    logger.debug(f"Failed to push message to monitoring subscriber: {exc}")
                    dead_sockets.append(socket)

            for dead in dead_sockets:
                self.active_connections.discard(dead)


monitoring_ws_manager = MonitoringWebSocketManager()
