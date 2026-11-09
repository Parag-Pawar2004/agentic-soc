"""Offline tests for intel import, guardrails, RAG and the agent pipeline."""
import asyncio

from app.intel.importer import infer_kind, parse_intel
from app.soar.policy import check_target


def test_infer_kind():
    assert infer_kind("8.8.8.8") == "ip"
    assert infer_kind("10.0.0.0/8") == "cidr"
    assert infer_kind("https://example.com/x") == "url"
    assert infer_kind("CVE-2024-3400") == "cve"
    assert infer_kind("a" * 64) == "hash"
    assert infer_kind("example.com") == "domain"
    assert infer_kind("free text") == "note"


def test_parse_csv_and_json():
    csv_text = "value,title,description,tags\n203.0.113.9,Bad host,Seen scanning,scan;demo\n,,,\n"
    rows = parse_intel(csv_text, "x.csv", "mylist")
    assert len(rows) == 1 and rows[0]["kind"] == "ip" and rows[0]["source"] == "mylist"
    assert rows[0]["tags"] == ["scan", "demo"]
    rows = parse_intel('[{"value": "evil.example.com", "text": "phishing kit"}]', "x.json")
    assert rows[0]["kind"] == "domain"


def test_policy_guards():
    assert check_target("block_ip", "10.1.2.3", []) is not None          # private
    assert check_target("block_ip", "8.8.8.8", ["8.8.8.0/24"]) is not None  # allowlisted
    assert check_target("block_ip", "1.2.3.4; rm -rf /", []) is not None  # injection-shaped
    assert check_target("block_ip", "203.0.113.45", []) is not None       # demo range, real alert
    assert check_target("block_ip", "203.0.113.45", [], simulated=True) is None
    assert check_target("suspend_user", "priya.sharma", []) is None
    assert check_target("suspend_user", "bad user$(x)", []) is not None
    assert check_target("format_disk", "x", []) is not None


def test_rag_finds_relevant_reference(settings):
    from app.service import SOCService

    service = SOCService(settings)
    assert service.bootstrap_intel() >= 10
    hits = service.rag.search("many failed ssh logins against different usernames", k=3)
    assert any("T1110" in h["title"] for h in hits[:2])


def _run(service, alert_payload):
    alert = service.db.create_alert(alert_payload)
    asyncio.run(service.run_pipeline(alert["id"]))
    return service.db.get_alert(alert["id"]), service.db.list_actions(alert_id=alert["id"])


def test_pipeline_bruteforce_to_approval_and_rollback(settings):
    from app import simulator
    from app.service import SOCService

    service = SOCService(settings)
    service.bootstrap_intel()
    alert, actions = _run(service, simulator.random_alert(0))
    assert alert["status"] == "awaiting_approval"
    assert alert["verdict"]["verdict"] == "malicious"
    assert alert["verdict"]["ioc_matches"], "demo IP should match seeded intel"
    blocks = [a for a in actions if a["type"] == "block_ip"]
    assert blocks and blocks[0]["target"] == "203.0.113.45" and blocks[0]["status"] == "pending"
    assert blocks[0]["provider"] == "mock"  # simulated alerts never touch real systems

    # nothing executes until approved
    assert not service.db.is_blocked("203.0.113.45")
    for a in actions:
        asyncio.run(service.decide(a["id"], approve=True, analyst="tester"))
    assert service.db.is_blocked("203.0.113.45")
    assert service.db.get_alert(alert["id"])["status"] == "resolved"

    # duplicate alert should not queue a second block
    _, again = _run(service, simulator.random_alert(0))
    assert not [a for a in again if a["type"] == "block_ip"]

    asyncio.run(service.unblock("203.0.113.45", "tester"))
    assert not service.db.is_blocked("203.0.113.45")

    traces = service.db.list_traces(alert["id"])
    agents = {t["agent"] for t in traces}
    assert {"supervisor", "threat_intel", "triage", "response", "reporter", "analyst", "soar"} <= agents


def test_pipeline_benign_backup_closes(settings):
    from app import simulator
    from app.service import SOCService

    service = SOCService(settings)
    service.bootstrap_intel()
    alert, actions = _run(service, simulator.random_alert(4))
    assert alert["status"] == "false_positive"
    assert actions == []


def test_reject_does_not_execute(settings):
    from app import simulator
    from app.service import SOCService

    service = SOCService(settings)
    service.bootstrap_intel()
    _, actions = _run(service, simulator.random_alert(3))
    assert actions
    done = asyncio.run(service.decide(actions[0]["id"], approve=False, analyst="tester"))
    assert done["status"] == "rejected"
    assert not service.db.is_blocked(actions[0]["target"])


def test_llm_json_extraction():
    from app.agents.nodes import normalise_analysis
    from app.llm import extract_json

    raw = extract_json('Sure!\n```json\n{"verdict": "malicious", "confidence": 1.7, "severity": "nope"}\n```')
    out = normalise_analysis(raw, {"verdict": "benign", "severity": "low", "confidence": 0.5, "summary": "",
                                   "reasoning": ["x"], "mitre": [], "recommended_actions": []})
    assert out["verdict"] == "malicious" and out["confidence"] == 1.0 and out["severity"] == "low"
