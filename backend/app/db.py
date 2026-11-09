"""SQLite persistence (stdlib only, no ORM) for alerts, traces, actions and intel."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'new',
    src_ip TEXT, dst_ip TEXT, username TEXT,
    simulated INTEGER NOT NULL DEFAULT 0,
    raw TEXT NOT NULL DEFAULT '{}',
    verdict TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE TABLE IF NOT EXISTS traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    agent TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT
);
CREATE INDEX IF NOT EXISTS idx_traces_alert ON traces(alert_id);
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    alert_id TEXT,
    created_at TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    provider TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    decided_by TEXT, decided_at TEXT,
    result TEXT
);
CREATE TABLE IF NOT EXISTS intel (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    title TEXT NOT NULL,
    text TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    url TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intel_value ON intel(value);
CREATE TABLE IF NOT EXISTS blocklist (
    target TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    provider TEXT NOT NULL,
    action_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _loads(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL") if self.path != ":memory:" else None
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ---- helpers -------------------------------------------------------
    def _exec(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def _all(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def _one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        rows = self._all(sql, params)
        return rows[0] if rows else None

    # ---- alerts --------------------------------------------------------
    def create_alert(self, alert: dict) -> dict:
        ts = now_iso()
        record = {
            "id": alert.get("id") or new_id("ALR"),
            "created_at": alert.get("created_at") or ts,
            "updated_at": ts,
            "source": alert.get("source", "api"),
            "category": alert.get("category", "network"),
            "title": alert.get("title", "Untitled alert"),
            "description": alert.get("description", ""),
            "severity": alert.get("severity", "medium"),
            "status": "new",
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "username": alert.get("username"),
            "simulated": 1 if alert.get("simulated") else 0,
            "raw": json.dumps(alert.get("raw", {})),
        }
        cols = ",".join(record)
        self._exec(f"INSERT INTO alerts ({cols}) VALUES ({','.join('?' * len(record))})", record.values())
        return self.get_alert(record["id"])  # type: ignore[return-value]

    def _alert_row(self, row: dict | None) -> dict | None:
        if not row:
            return None
        row["raw"] = _loads(row.get("raw"), {})
        row["verdict"] = _loads(row.get("verdict"))
        row["simulated"] = bool(row.get("simulated"))
        return row

    def get_alert(self, alert_id: str) -> dict | None:
        return self._alert_row(self._one("SELECT * FROM alerts WHERE id=?", [alert_id]))

    def list_alerts(self, limit: int = 100, status: str | None = None) -> list[dict]:
        if status:
            rows = self._all("SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC LIMIT ?", [status, limit])
        else:
            rows = self._all("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", [limit])
        return [self._alert_row(r) for r in rows]  # type: ignore[misc]

    def update_alert(self, alert_id: str, **fields: Any) -> None:
        if "verdict" in fields and not isinstance(fields["verdict"], str):
            fields["verdict"] = json.dumps(fields["verdict"])
        fields["updated_at"] = now_iso()
        sets = ",".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE alerts SET {sets} WHERE id=?", [*fields.values(), alert_id])

    # ---- traces --------------------------------------------------------
    def add_trace(self, event: dict) -> dict:
        cur = self._exec(
            "INSERT INTO traces (alert_id, ts, agent, kind, message, data) VALUES (?,?,?,?,?,?)",
            [event["alert_id"], event["ts"], event["agent"], event["kind"], event["message"],
             json.dumps(event.get("data")) if event.get("data") is not None else None],
        )
        return {**event, "id": cur.lastrowid}

    def list_traces(self, alert_id: str) -> list[dict]:
        rows = self._all("SELECT * FROM traces WHERE alert_id=? ORDER BY id", [alert_id])
        for r in rows:
            r["data"] = _loads(r.get("data"))
        return rows

    # ---- actions -------------------------------------------------------
    def create_action(self, action: dict) -> dict:
        record = {
            "id": action.get("id") or new_id("ACT"),
            "alert_id": action.get("alert_id"),
            "created_at": now_iso(),
            "type": action["type"],
            "target": action["target"],
            "provider": action["provider"],
            "reason": action.get("reason", ""),
            "status": action.get("status", "pending"),
        }
        cols = ",".join(record)
        self._exec(f"INSERT INTO actions ({cols}) VALUES ({','.join('?' * len(record))})", record.values())
        return self.get_action(record["id"])  # type: ignore[return-value]

    def _action_row(self, row: dict | None) -> dict | None:
        if row:
            row["result"] = _loads(row.get("result"))
        return row

    def get_action(self, action_id: str) -> dict | None:
        return self._action_row(self._one("SELECT * FROM actions WHERE id=?", [action_id]))

    def list_actions(self, status: str | None = None, alert_id: str | None = None, limit: int = 200) -> list[dict]:
        clauses, params = [], []
        if status:
            clauses.append("status=?")
            params.append(status)
        if alert_id:
            clauses.append("alert_id=?")
            params.append(alert_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._all(f"SELECT * FROM actions {where} ORDER BY created_at DESC LIMIT ?", [*params, limit])
        return [self._action_row(r) for r in rows]  # type: ignore[misc]

    def update_action(self, action_id: str, **fields: Any) -> None:
        if "result" in fields and not isinstance(fields["result"], str):
            fields["result"] = json.dumps(fields["result"])
        sets = ",".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE actions SET {sets} WHERE id=?", [*fields.values(), action_id])

    def pending_action_exists(self, type_: str, target: str) -> bool:
        return self._one(
            "SELECT id FROM actions WHERE type=? AND target=? AND status IN ('pending','approved')", [type_, target]
        ) is not None

    # ---- blocklist (mock firewall + record of real blocks) ---------------
    def add_block(self, target: str, kind: str, provider: str, action_id: str | None) -> None:
        self._exec(
            "INSERT OR REPLACE INTO blocklist (target, kind, provider, action_id, created_at) VALUES (?,?,?,?,?)",
            [target, kind, provider, action_id, now_iso()],
        )

    def remove_block(self, target: str) -> None:
        self._exec("DELETE FROM blocklist WHERE target=?", [target])

    def is_blocked(self, target: str) -> bool:
        return self._one("SELECT target FROM blocklist WHERE target=?", [target]) is not None

    def list_blocks(self) -> list[dict]:
        return self._all("SELECT * FROM blocklist ORDER BY created_at DESC")

    # ---- intel -----------------------------------------------------------
    def upsert_intel(self, records: list[dict]) -> int:
        ts = now_iso()
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO intel (id, source, kind, value, title, text, tags, url, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (r["id"], r["source"], r["kind"], r["value"], r["title"], r["text"],
                     json.dumps(r.get("tags", [])), r.get("url"), ts)
                    for r in records
                ],
            )
            self._conn.commit()
        return len(records)

    def find_intel_by_value(self, value: str) -> list[dict]:
        rows = self._all("SELECT * FROM intel WHERE value=? LIMIT 20", [value])
        for r in rows:
            r["tags"] = _loads(r.get("tags"), [])
        return rows

    def get_intel(self, ids: list[str]) -> dict[str, dict]:
        if not ids:
            return {}
        rows = self._all(f"SELECT * FROM intel WHERE id IN ({','.join('?' * len(ids))})", ids)
        out = {}
        for r in rows:
            r["tags"] = _loads(r.get("tags"), [])
            out[r["id"]] = r
        return out

    def intel_counts(self) -> dict[str, int]:
        return {r["source"]: r["n"] for r in self._all("SELECT source, COUNT(*) AS n FROM intel GROUP BY source")}

    def all_intel(self) -> list[dict]:
        return self._all("SELECT id, title, text, source, kind, value FROM intel")

    # ---- feed status / audit ----------------------------------------------
    def audit(self, actor: str, event: str, detail: Any = None) -> None:
        self._exec(
            "INSERT INTO audit (ts, actor, event, detail) VALUES (?,?,?,?)",
            [now_iso(), actor, event, json.dumps(detail) if detail is not None else None],
        )

    def list_audit(self, limit: int = 200) -> list[dict]:
        rows = self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", [limit])
        for r in rows:
            r["detail"] = _loads(r.get("detail"))
        return rows

    # ---- stats -------------------------------------------------------------
    def stats(self) -> dict:
        sev = {r["severity"]: r["n"] for r in self._all("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")}
        status = {r["status"]: r["n"] for r in self._all("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")}
        daily = self._all(
            "SELECT substr(created_at,1,13) AS hour, COUNT(*) AS n FROM alerts "
            "GROUP BY hour ORDER BY hour DESC LIMIT 24"
        )
        return {
            "alerts_total": sum(status.values()),
            "alerts_by_severity": sev,
            "alerts_by_status": status,
            "alerts_by_hour": list(reversed(daily)),
            "pending_actions": len(self.list_actions(status="pending")),
            "blocked_targets": len(self.list_blocks()),
            "intel_records": sum(self.intel_counts().values()),
        }
