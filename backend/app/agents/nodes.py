"""Specialist agents. Each node reads/writes the shared state and narrates its
reasoning through `ctx.trace(...)`, which streams to the dashboard live."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, TypedDict

from ..llm import LLMUnavailable, chat_json, resolve_provider
from ..soar.policy import check_target
from ..soar.providers import provider_for

SEVERITIES = ["low", "medium", "high", "critical"]


class SOCState(TypedDict, total=False):
    alert: dict
    domain: str
    indicators: dict
    ioc_matches: list
    intel_hits: list
    analysis: dict
    proposals: list
    route: str


@dataclass
class AgentContext:
    settings: Any
    db: Any
    rag: Any
    broker: Any

    def trace(self, alert_id: str, agent: str, kind: str, message: str, data: Any = None) -> None:
        self.broker.trace(alert_id, agent, kind, message, data)


# ------------------------------------------------------------------ helpers
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_HASH = re.compile(r"\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|co|me|cc|tk)\b", re.I)


def extract_indicators(alert: dict) -> dict:
    blob = " ".join([alert.get("title", ""), alert.get("description", ""), json.dumps(alert.get("raw", {}))])
    ips = {ip for ip in _IP.findall(blob) if _valid_ip(ip)}
    for key in ("src_ip", "dst_ip"):
        if alert.get(key):
            ips.add(alert[key])
    users = {alert["username"]} if alert.get("username") else set()
    return {
        "ips": sorted(ips),
        "external_ips": sorted(ip for ip in ips if _is_external(ip)),
        "users": sorted(users),
        "cves": sorted({c.upper() for c in _CVE.findall(blob)}),
        "hashes": sorted({h.lower() for h in _HASH.findall(blob)}),
        "domains": sorted({d.lower() for d in _DOMAIN.findall(blob)} - ips),
    }


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_DEMO = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global or any(addr in n for n in _DEMO)


def classify_domain(alert: dict) -> str:
    text = f"{alert.get('category', '')} {alert.get('title', '')} {alert.get('description', '')}".lower()
    if any(k in text for k in ("login", "sign-in", "signin", "mfa", "okta", "identity", "account", "travel", "iam")):
        return "identity"
    if any(k in text for k in ("ransom", "malware", "process", "endpoint", "edr", "encrypt")):
        return "endpoint"
    return "network"


def _bump(sev: str, steps: int = 1) -> str:
    i = SEVERITIES.index(sev) if sev in SEVERITIES else 1
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, i + steps))]


# ------------------------------------------------------------------ heuristic analyst (no-LLM fallback)
_SIGNALS = [
    ("ransom", 0.45, "T1486", "ransomware-like file activity"),
    ("encrypt", 0.25, "T1486", "mass encryption indicators"),
    ("beacon", 0.35, "T1071", "periodic beaconing to an external host"),
    ("exfil", 0.35, "T1041", "possible data exfiltration"),
    ("brute", 0.3, "T1110", "brute-force authentication pattern"),
    ("failed login", 0.25, "T1110", "repeated failed logins"),
    ("password spray", 0.3, "T1110", "password spraying"),
    ("impossible travel", 0.35, "T1078", "impossible-travel sign-in"),
    ("mfa", 0.15, "T1078", "MFA anomalies"),
    ("exploit", 0.3, "T1190", "exploit attempt against a public service"),
    ("sql injection", 0.3, "T1190", "SQL injection payloads"),
    ("scan", 0.1, "T1046", "port/service scanning"),
    ("phish", 0.25, "T1566", "phishing indicators"),
]
_BENIGN = [("scheduled", "matches a scheduled job"), ("backup", "consistent with backup traffic"),
           ("vulnerability scanner", "internal vulnerability scanner"), ("health check", "health-check traffic")]


def heuristic_analysis(state: SOCState) -> dict:
    alert = state["alert"]
    text = f"{alert.get('title', '')} {alert.get('description', '')} {json.dumps(alert.get('raw', {}))}".lower()
    score, mitre, reasons = 0.1, [], []
    for keyword, weight, technique, why in _SIGNALS:
        if keyword in text:
            score += weight
            reasons.append(f"Alert text shows {why}.")
            if technique not in mitre:
                mitre.append(technique)
    if state.get("ioc_matches"):
        score += 0.35
        reasons.append(f"{len(state['ioc_matches'])} indicator(s) match known threat intelligence.")
    attempts = alert.get("raw", {}).get("failed_attempts")
    if isinstance(attempts, (int, float)) and attempts >= 20:
        score += 0.2
        reasons.append(f"{int(attempts)} failed attempts is far above normal user error.")
    for keyword, why in _BENIGN:
        if keyword in text:
            score -= 0.35
            reasons.append(f"Activity {why}, which is a common benign cause.")
    if state.get("intel_hits"):
        reasons.append(f"Closest reference: “{state['intel_hits'][0]['title']}”.")
    score = max(0.0, min(1.0, score))
    verdict = "malicious" if score >= 0.6 else "suspicious" if score >= 0.35 else "benign"
    severity = alert.get("severity", "medium")
    if verdict == "malicious" and severity in ("low", "medium"):
        severity = _bump(severity)
    if verdict == "benign":
        severity = "low"
    confidence = round(0.55 + abs(score - 0.45) * 0.8, 2)
    return {
        "verdict": verdict,
        "severity": severity,
        "confidence": min(confidence, 0.95),
        "summary": f"Heuristic triage rated this {verdict} (risk score {score:.2f}).",
        "reasoning": reasons or ["No strong malicious signals found in the alert."],
        "mitre": mitre,
        "recommended_actions": default_recommendations(state, verdict),
    }


def default_recommendations(state: SOCState, verdict: str) -> list[dict]:
    if verdict == "benign":
        return []
    alert, ind, domain = state["alert"], state.get("indicators", {}), state.get("domain", "network")
    recs = []
    text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
    src, dst = alert.get("src_ip"), alert.get("dst_ip")
    if src and src in ind.get("external_ips", []):
        recs.append({"type": "block_ip", "target": src, "reason": "External source of the malicious activity"})
    if dst and dst in ind.get("external_ips", []) and any(k in text for k in ("beacon", "exfil", "c2", "command")):
        recs.append({"type": "block_ip", "target": dst, "reason": "External destination receiving suspicious traffic"})
    user = alert.get("username")
    if user and domain in ("identity", "endpoint"):
        recs.append({"type": "revoke_sessions", "target": user, "reason": "Contain a possibly compromised account"})
        if verdict == "malicious":
            recs.append({"type": "suspend_user", "target": user, "reason": "High-confidence account compromise"})
    return recs


TRIAGE_SYSTEM = """You are a senior SOC analyst agent. Analyse the alert using the enrichment and the
retrieved threat-intelligence context. Think step by step, then respond with ONLY a JSON object:
{
 "verdict": "malicious" | "suspicious" | "benign",
 "severity": "low" | "medium" | "high" | "critical",
 "confidence": number between 0 and 1,
 "summary": "one or two sentences",
 "reasoning": ["short step 1", "short step 2", "..."],
 "mitre": ["T1110", "..."],
 "recommended_actions": [
   {"type": "block_ip" | "revoke_sessions" | "suspend_user" | "disable_access_keys",
    "target": "IP address or username taken from the alert", "reason": "why"}
 ]
}
Rules: only recommend actions on targets that appear in the alert; never block private or internal IPs;
prefer the least disruptive action; recommend nothing for benign alerts."""


def normalise_analysis(raw: dict, fallback: dict) -> dict:
    out = dict(fallback)
    verdict = str(raw.get("verdict", "")).lower()
    if verdict in {"malicious", "suspicious", "benign"}:
        out["verdict"] = verdict
    sev = str(raw.get("severity", "")).lower()
    if sev in SEVERITIES:
        out["severity"] = sev
    try:
        out["confidence"] = round(max(0.0, min(1.0, float(raw.get("confidence", out["confidence"])))), 2)
    except (TypeError, ValueError):
        pass
    if isinstance(raw.get("summary"), str) and raw["summary"].strip():
        out["summary"] = raw["summary"].strip()[:600]
    if isinstance(raw.get("reasoning"), list) and raw["reasoning"]:
        out["reasoning"] = [str(s)[:400] for s in raw["reasoning"][:10]]
    if isinstance(raw.get("mitre"), list):
        out["mitre"] = [str(t)[:20] for t in raw["mitre"][:8]]
    if isinstance(raw.get("recommended_actions"), list):
        acts = []
        for a in raw["recommended_actions"][:6]:
            if isinstance(a, dict) and a.get("type") and a.get("target"):
                acts.append({"type": str(a["type"]), "target": str(a["target"]).strip(),
                             "reason": str(a.get("reason", ""))[:300]})
        out["recommended_actions"] = acts
    return out


# ------------------------------------------------------------------ nodes
def make_nodes(ctx: AgentContext):
    async def supervisor(state: SOCState) -> SOCState:
        alert = state["alert"]
        aid = alert["id"]
        ctx.db.update_alert(aid, status="triaging")
        ctx.trace(aid, "supervisor", "thought", f"New alert from {alert.get('source')}: {alert.get('title')}")
        indicators = extract_indicators(alert)
        domain = classify_domain(alert)
        found = {k: v for k, v in indicators.items() if v and k != "ips"}
        ctx.trace(aid, "supervisor", "tool", "Extracted indicators", found)
        ctx.trace(aid, "supervisor", "decision",
                  f"Routing to the {domain} playbook → threat-intel agent, then triage agent")
        return {"indicators": indicators, "domain": domain}

    async def intel_agent(state: SOCState) -> SOCState:
        alert, ind = state["alert"], state["indicators"]
        aid = alert["id"]
        matches = []
        lookups = ind["external_ips"] + ind["cves"] + ind["hashes"] + ind["domains"]
        cidrs = [r for r in ctx.db.all_intel() if r["kind"] == "cidr"]
        for value in lookups:
            hits = ctx.db.find_intel_by_value(value)
            if value in ind["external_ips"]:
                addr = ipaddress.ip_address(value)
                for r in cidrs:
                    try:
                        if addr in ipaddress.ip_network(r["value"], strict=False):
                            hits.append(r)
                    except ValueError:
                        continue
            for h in hits:
                matches.append({"indicator": value, "source": h["source"], "title": h["title"]})
        if matches:
            ctx.trace(aid, "threat_intel", "result", f"{len(matches)} indicator match(es) in the intel store", matches[:8])
        else:
            ctx.trace(aid, "threat_intel", "result", f"No exact intel matches for {len(lookups)} indicator(s)")
        query = f"{alert.get('title', '')}. {alert.get('description', '')}"
        hits = ctx.rag.search(query, k=4)
        ctx.trace(aid, "threat_intel", "tool", f"RAG search over {ctx.rag.backend} returned {len(hits)} passages",
                  [{"title": h["title"], "score": h["score"], "source": h["source"]} for h in hits])
        return {"ioc_matches": matches, "intel_hits": hits}

    async def triage_agent(state: SOCState) -> SOCState:
        alert = state["alert"]
        aid = alert["id"]
        fallback = heuristic_analysis(state)
        analysis = fallback
        provider = resolve_provider(ctx.settings)
        if provider != "none":
            ctx.trace(aid, "triage", "thought", f"Asking {ctx.settings.llm_label} to analyse the alert")
            context = "\n\n".join(f"[{h['source']}] {h['title']}: {h['text']}" for h in state.get("intel_hits", []))
            prompt = json.dumps({
                "alert": {k: alert.get(k) for k in ("title", "description", "category", "severity", "src_ip",
                                                    "dst_ip", "username", "source", "raw")},
                "indicators": state.get("indicators"),
                "intel_matches": state.get("ioc_matches", []),
            }, default=str) + f"\n\nRetrieved threat-intelligence context:\n{context or 'none'}"
            try:
                raw, label = await chat_json(ctx.settings, TRIAGE_SYSTEM, prompt)
                analysis = normalise_analysis(raw, fallback)
                analysis["engine"] = label
            except LLMUnavailable as exc:
                ctx.trace(aid, "triage", "error", f"LLM unavailable ({exc}); using heuristic analyst")
                analysis["engine"] = "heuristic"
        else:
            analysis["engine"] = "heuristic"
        for step in analysis["reasoning"]:
            ctx.trace(aid, "triage", "thought", step)
        ctx.trace(aid, "triage", "decision",
                  f"Verdict: {analysis['verdict'].upper()} · severity {analysis['severity']} · "
                  f"confidence {analysis['confidence']:.0%}", {"mitre": analysis.get("mitre", [])})
        route = "report" if analysis["verdict"] == "benign" and analysis["confidence"] >= 0.7 else "respond"
        return {"analysis": analysis, "route": route}

    async def response_agent(state: SOCState) -> SOCState:
        alert, analysis = state["alert"], state["analysis"]
        aid = alert["id"]
        proposals = []
        seen = set()
        for rec in analysis.get("recommended_actions", []):
            key = (rec["type"], rec["target"])
            if key in seen:
                continue
            seen.add(key)
            reason = check_target(rec["type"], rec["target"], ctx.settings.ip_allowlist, alert.get("simulated", False))
            if reason:
                ctx.trace(aid, "response", "error", f"Rejected {rec['type']} {rec['target']}: {reason}")
                continue
            if rec["type"] == "block_ip" and ctx.db.is_blocked(rec["target"]):
                ctx.trace(aid, "response", "result", f"{rec['target']} is already blocked; skipping")
                continue
            if ctx.db.pending_action_exists(rec["type"], rec["target"]):
                ctx.trace(aid, "response", "result", f"A {rec['type']} for {rec['target']} is already queued")
                continue
            provider = provider_for(rec["type"], ctx.settings, alert.get("simulated", False))
            action = ctx.db.create_action({"alert_id": aid, "type": rec["type"], "target": rec["target"],
                                           "provider": provider, "reason": rec.get("reason", "")})
            proposals.append(action)
            ctx.broker.notify("action", action)
            ctx.trace(aid, "response", "decision",
                      f"Proposed {rec['type'].replace('_', ' ')} → {rec['target']} via {provider} (awaiting approval)",
                      {"action_id": action["id"]})
        if not proposals:
            ctx.trace(aid, "response", "result", "No containment actions proposed")
        return {"proposals": proposals}

    async def reporter(state: SOCState) -> SOCState:
        alert, analysis = state["alert"], state["analysis"]
        aid = alert["id"]
        proposals = state.get("proposals", [])
        if analysis["verdict"] == "benign":
            status = "false_positive"
        elif proposals:
            status = "awaiting_approval"
        else:
            status = "triaged"
        verdict = {**analysis, "ioc_matches": state.get("ioc_matches", []),
                   "intel_refs": [{"title": h["title"], "source": h["source"], "score": h["score"]}
                                  for h in state.get("intel_hits", [])],
                   "domain": state.get("domain")}
        ctx.db.update_alert(aid, status=status, severity=analysis["severity"], verdict=verdict)
        ctx.trace(aid, "reporter", "result", f"Case updated → {status.replace('_', ' ')}. {analysis['summary']}")
        ctx.broker.notify("alert", ctx.db.get_alert(aid))
        return {}

    return {"supervisor": supervisor, "threat_intel": intel_agent, "triage": triage_agent,
            "response": response_agent, "reporter": reporter}
