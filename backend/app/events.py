"""In-process pub/sub used to stream agent reasoning traces to WebSocket clients."""
from __future__ import annotations

import asyncio
from typing import Any

from .db import Database, now_iso


class EventBroker:
    def __init__(self, db: Database | None = None):
        self.db = db
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: dict) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:  # slow client: drop oldest
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except Exception:
                    pass

    def trace(self, alert_id: str, agent: str, kind: str, message: str, data: Any = None) -> dict:
        """Record one reasoning step (persisted + broadcast)."""
        event = {"alert_id": alert_id, "ts": now_iso(), "agent": agent, "kind": kind, "message": message, "data": data}
        if self.db is not None:
            event = self.db.add_trace(event)
        self.publish({"type": "trace", "payload": event})
        return event

    def notify(self, type_: str, payload: Any) -> None:
        self.publish({"type": type_, "payload": payload})
