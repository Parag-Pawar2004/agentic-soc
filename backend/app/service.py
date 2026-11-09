"""The SOC service: wires DB, event broker, RAG and the agent graph together."""
from __future__ import annotations

import asyncio
import logging

from .agents.nodes import AgentContext
from .config import BACKEND_DIR
from .db import Database, now_iso
from .events import EventBroker
from .intel import importer
from .rag import ThreatIntelRAG
from .soar import providers
from .soar.policy import check_target

log = logging.getLogger("soc.service")


class SOCService:
    def __init__(self, settings, graph_builder=None):
        self.settings = settings
        self.db = Database(settings.database_path)
        self.broker = EventBroker(self.db)
        self.rag = ThreatIntelRAG(settings, self.db)
        self.ctx = AgentContext(settings, self.db, self.rag, self.broker)
        if graph_builder is None:
            from .agents.graph import build_graph as graph_builder
        self.graph = graph_builder(self.ctx)
        self._tasks: set[asyncio.Task] = set()

    # ---------------------------------------------------------------- intel
    def bootstrap_intel(self) -> int:
        """Load bundled reference notes + any files in INTEL_IMPORT_DIR."""
        records = importer.load_seed(BACKEND_DIR / "data" / "seed_intel.json")
        for path in importer.files_in(self.settings.intel_import_dir):
            try:
                records += importer.parse_intel(path.read_text(encoding="utf-8"), path.name, default_source=path.stem)
            except Exception as exc:
                log.warning("skipping %s: %s", path.name, exc)
        return self.add_intel(records)

    def add_intel(self, records: list[dict]) -> int:
        if not records:
            return 0
        self.db.upsert_intel(records)
        self.rag.index(records)
        return len(records)

    # ---------------------------------------------------------------- alerts
    def ingest_alert(self, payload: dict) -> dict:
        alert = self.db.create_alert(payload)
        self.broker.notify("alert", alert)
        self.start_pipeline(alert["id"])
        return alert

    def start_pipeline(self, alert_id: str) -> None:
        """Run triage in the background, keeping a reference so the task isn't garbage-collected."""
        task = asyncio.create_task(self.run_pipeline(alert_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def run_pipeline(self, alert_id: str) -> dict:
        alert = self.db.get_alert(alert_id)
        try:
            return await self.graph.ainvoke({"alert": alert})
        except Exception as exc:  # never leave an alert stuck in "triaging"
            log.exception("pipeline failed for %s", alert_id)
            self.broker.trace(alert_id, "supervisor", "error", f"Pipeline error: {exc}")
            self.db.update_alert(alert_id, status="error")
            self.broker.notify("alert", self.db.get_alert(alert_id))
            return {}

    # ---------------------------------------------------------------- approvals
    async def decide(self, action_id: str, approve: bool, analyst: str) -> dict:
        action = self.db.get_action(action_id)
        if not action:
            raise KeyError(action_id)
        if action["status"] != "pending":
            raise ValueError(f"action is already {action['status']}")
        self.db.update_action(action_id, status="approved" if approve else "rejected",
                              decided_by=analyst, decided_at=now_iso())
        self.db.audit(analyst, "approve_action" if approve else "reject_action",
                      {"action_id": action_id, "type": action["type"], "target": action["target"]})
        if action["alert_id"]:
            self.broker.trace(action["alert_id"], "analyst", "decision",
                              f"{analyst} {'approved' if approve else 'rejected'} {action['type']} → {action['target']}")
        if approve:
            await self._execute(action_id, analyst)
        self._refresh_alert_status(action["alert_id"])
        updated = self.db.get_action(action_id)
        self.broker.notify("action", updated)
        return updated

    async def _execute(self, action_id: str, actor: str) -> None:
        action = self.db.get_action(action_id)
        try:
            result = await providers.execute(action, self.settings, self.db)
            if action["provider"] != "mock" and action["type"] == "block_ip":
                self.db.add_block(action["target"], "ip", action["provider"], action_id)
            if action["provider"] != "mock" and action["type"] == "unblock_ip":
                self.db.remove_block(action["target"])
            self.db.update_action(action_id, status="executed", result=result)
            msg, kind = f"Executed {action['type']} → {action['target']}: {result.get('message')}", "result"
        except Exception as exc:
            self.db.update_action(action_id, status="failed", result={"error": str(exc)})
            msg, kind = f"Execution failed for {action['type']} → {action['target']}: {exc}", "error"
        self.db.audit(actor, "execute_action", {"action_id": action_id, "message": msg})
        if action["alert_id"]:
            self.broker.trace(action["alert_id"], "soar", kind, msg)

    def _refresh_alert_status(self, alert_id: str | None) -> None:
        if not alert_id:
            return
        actions = self.db.list_actions(alert_id=alert_id)
        if actions and not any(a["status"] == "pending" for a in actions):
            self.db.update_alert(alert_id, status="resolved")
            self.broker.notify("alert", self.db.get_alert(alert_id))

    async def unblock(self, target: str, analyst: str) -> dict:
        block = next((b for b in self.db.list_blocks() if b["target"] == target), None)
        if not block:
            raise KeyError(target)
        if block["kind"] == "user":  # simulated suspension
            self.db.remove_block(target)
            self.db.audit(analyst, "unsuspend_user", {"target": target})
            return {"status": "executed", "target": target}
        reason = check_target("unblock_ip", target, [], simulated=block["provider"] == "mock")
        if reason:
            raise ValueError(reason)
        action = self.db.create_action({"alert_id": None, "type": "unblock_ip", "target": target,
                                        "provider": block["provider"], "reason": f"Manual rollback by {analyst}",
                                        "status": "approved"})
        await self._execute(action["id"], analyst)
        return self.db.get_action(action["id"])
