// In-browser stand-in for the backend, used when NEXT_PUBLIC_DEMO_MODE=1.
// It replays the same agent steps the real pipeline produces with the built-in
// heuristic analyst, so the dashboard can be explored without installing anything.
import type { Action, Alert, AuditEntry, Block, IntelRecord, SocApi, StreamEvent, Trace } from "./types";

type Step = [agent: string, kind: Trace["kind"], message: string, data?: unknown];
interface Scenario {
  alert: Omit<Alert, "id" | "created_at" | "status" | "simulated" | "verdict">;
  steps: Step[];
  verdict: NonNullable<Alert["verdict"]>;
  actions: { type: string; target: string; reason: string }[];
}

const SCENARIOS: Scenario[] = [
  {
    alert: {
      source: "sshd", category: "authentication", severity: "high",
      title: "SSH brute force: 214 failed logins from one host",
      description: "Failed login burst against 37 different usernames on bastion-01 within 4 minutes, followed by one successful login for user deploy.",
      src_ip: "203.0.113.45", dst_ip: "10.0.4.12", username: "deploy",
      raw: { failed_attempts: 214, distinct_users: 37, service: "ssh", success_after_failures: true },
    },
    steps: [
      ["supervisor", "thought", "New alert from sshd: SSH brute force: 214 failed logins from one host"],
      ["supervisor", "tool", "Extracted indicators", { external_ips: ["203.0.113.45"], users: ["deploy"] }],
      ["supervisor", "decision", "Routing to the identity playbook → threat-intel agent, then triage agent"],
      ["threat_intel", "result", "1 indicator match in the intel store", [{ indicator: "203.0.113.45", source: "demo", title: "Demo indicator: brute-force source" }]],
      ["threat_intel", "tool", "RAG search returned 4 passages", [{ title: "Brute force against authentication (ATT&CK T1110)", score: 0.44 }, { title: "Use of valid accounts / suspicious sign-in (ATT&CK T1078)", score: 0.31 }]],
      ["triage", "thought", "214 failed attempts across 37 usernames is password spraying, not user error."],
      ["triage", "thought", "A successful login for 'deploy' right after the burst suggests the spray worked."],
      ["triage", "thought", "The source address matches known threat intelligence."],
      ["triage", "decision", "Verdict: MALICIOUS · severity high · confidence 95%", { mitre: ["T1110", "T1078"] }],
    ],
    verdict: {
      verdict: "malicious", severity: "high", confidence: 0.95, engine: "OpenRouter · llama-3.3-70b-instruct:free",
      summary: "Password spray from a known-bad host succeeded against the deploy account on bastion-01.",
      reasoning: [], mitre: ["T1110", "T1078"],
    },
    actions: [
      { type: "block_ip", target: "203.0.113.45", reason: "External source of the password spray" },
      { type: "revoke_sessions", target: "deploy", reason: "Account logged in right after the spray" },
    ],
  },
  {
    alert: {
      source: "zeek", category: "network", severity: "medium",
      title: "Periodic beacon from workstation to rare external host",
      description: "Host ws-fin-22 contacted the same external server every 60s (±2s) for 6 hours with ~400 byte requests. Destination seen by no other host.",
      src_ip: "10.0.8.22", dst_ip: "198.51.100.23", username: null,
      raw: { interval_seconds: 60, jitter: 2, duration_hours: 6 },
    },
    steps: [
      ["supervisor", "thought", "New alert from zeek: Periodic beacon from workstation to rare external host"],
      ["supervisor", "tool", "Extracted indicators", { external_ips: ["198.51.100.23"] }],
      ["supervisor", "decision", "Routing to the network playbook → threat-intel agent, then triage agent"],
      ["threat_intel", "result", "1 indicator match in the intel store", [{ indicator: "198.51.100.23", source: "demo", title: "Demo indicator: beaconing destination" }]],
      ["threat_intel", "tool", "RAG search returned 4 passages", [{ title: "Command-and-control beaconing (ATT&CK T1071)", score: 0.4 }]],
      ["triage", "thought", "A 60-second interval with ±2s jitter over six hours is machine-driven, not a person browsing."],
      ["triage", "thought", "Only one internal host talks to this destination, which fits a single infected machine."],
      ["triage", "decision", "Verdict: MALICIOUS · severity high · confidence 83%", { mitre: ["T1071"] }],
    ],
    verdict: {
      verdict: "malicious", severity: "high", confidence: 0.83, engine: "OpenRouter · llama-3.3-70b-instruct:free",
      summary: "ws-fin-22 shows command-and-control beaconing to a known-bad external host.",
      reasoning: [], mitre: ["T1071"],
    },
    actions: [{ type: "block_ip", target: "198.51.100.23", reason: "External destination receiving the beacon" }],
  },
  {
    alert: {
      source: "okta", category: "identity", severity: "high",
      title: "Impossible travel sign-in with MFA push fatigue",
      description: "User priya.sharma signed in from Pune and, 18 minutes later, from an anonymising network abroad after rejecting 9 MFA pushes and approving the 10th.",
      src_ip: "203.0.113.200", dst_ip: null, username: "priya.sharma",
      raw: { mfa_pushes: 10, minutes_between_logins: 18 },
    },
    steps: [
      ["supervisor", "thought", "New alert from okta: Impossible travel sign-in with MFA push fatigue"],
      ["supervisor", "tool", "Extracted indicators", { external_ips: ["203.0.113.200"], users: ["priya.sharma"] }],
      ["supervisor", "decision", "Routing to the identity playbook → threat-intel agent, then triage agent"],
      ["threat_intel", "result", "1 indicator match in the intel store", [{ indicator: "203.0.113.200", source: "demo", title: "Demo indicator: abusive network block" }]],
      ["threat_intel", "tool", "RAG search returned 4 passages", [{ title: "Use of valid accounts / suspicious sign-in (ATT&CK T1078)", score: 0.47 }]],
      ["triage", "thought", "Pune to another country in 18 minutes is physically impossible."],
      ["triage", "thought", "Nine rejected pushes then an approval is the classic MFA-fatigue pattern."],
      ["triage", "decision", "Verdict: MALICIOUS · severity high · confidence 91%", { mitre: ["T1078", "T1621"] }],
    ],
    verdict: {
      verdict: "malicious", severity: "high", confidence: 0.91, engine: "OpenRouter · llama-3.3-70b-instruct:free",
      summary: "priya.sharma's account was likely taken over through MFA push fatigue.",
      reasoning: [], mitre: ["T1078", "T1621"],
    },
    actions: [
      { type: "revoke_sessions", target: "priya.sharma", reason: "Kick the attacker out of active sessions" },
      { type: "suspend_user", target: "priya.sharma", reason: "Hold the account until the owner is verified" },
      { type: "block_ip", target: "203.0.113.200", reason: "Anonymising network used for the sign-in" },
    ],
  },
  {
    alert: {
      source: "firewall", category: "network", severity: "low",
      title: "Large outbound transfer from backup server",
      description: "backup-02 sent 48 GB to the offsite storage provider during the scheduled nightly backup window.",
      src_ip: "10.0.9.2", dst_ip: "192.0.2.80", username: "svc-backup",
      raw: { bytes: 48000000000, window: "scheduled 01:00-03:00" },
    },
    steps: [
      ["supervisor", "thought", "New alert from firewall: Large outbound transfer from backup server"],
      ["supervisor", "tool", "Extracted indicators", { external_ips: ["192.0.2.80"], users: ["svc-backup"] }],
      ["supervisor", "decision", "Routing to the network playbook → threat-intel agent, then triage agent"],
      ["threat_intel", "result", "No exact intel matches for 1 indicator"],
      ["threat_intel", "tool", "RAG search returned 4 passages", [{ title: "Common false positives", score: 0.38 }]],
      ["triage", "thought", "The transfer happened inside the scheduled backup window."],
      ["triage", "thought", "The account is the backup service account and the destination has no bad reputation."],
      ["triage", "decision", "Verdict: BENIGN · severity low · confidence 91%", { mitre: [] }],
    ],
    verdict: {
      verdict: "benign", severity: "low", confidence: 0.91, engine: "OpenRouter · llama-3.3-70b-instruct:free",
      summary: "Expected nightly backup traffic; closed as a false positive.",
      reasoning: [], mitre: [],
    },
    actions: [],
  },
];

const INTEL: IntelRecord[] = [
  { id: "r1", source: "reference", kind: "note", value: "T1110", title: "Brute force against authentication (ATT&CK T1110)", tags: ["credential-access"], text: "Many failed logins from one source in a short window, often against SSH, RDP, VPN or web login pages." },
  { id: "r2", source: "reference", kind: "note", value: "T1078", title: "Use of valid accounts / suspicious sign-in (ATT&CK T1078)", tags: ["identity"], text: "A legitimate account signs in from an unusual country, impossible-travel location, new device or anonymising network." },
  { id: "r3", source: "reference", kind: "note", value: "T1071", title: "Command-and-control beaconing (ATT&CK T1071)", tags: ["c2"], text: "An internal host contacts the same external address at very regular intervals with small, similar-sized requests." },
  { id: "r4", source: "reference", kind: "note", value: "T1486", title: "Ransomware behaviour (ATT&CK T1486)", tags: ["impact"], text: "Rapid renaming or rewriting of many files, deletion of backups or shadow copies, and ransom notes appearing." },
  { id: "r5", source: "reference", kind: "note", value: "benign-patterns", title: "Common false positives", tags: ["triage"], text: "Vulnerability scanners, uptime monitors, backup jobs producing large transfers, users mistyping passwords a few times." },
  { id: "r6", source: "demo", kind: "ip", value: "203.0.113.45", title: "Demo indicator: brute-force source", tags: ["demo"], text: "Documentation-range address used by the built-in simulator." },
];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const iso = (offsetMin = 0) => new Date(Date.now() - offsetMin * 60000).toISOString().slice(0, 19) + "+00:00";
let seq = 100;
const id = (p: string) => `${p}-${(seq++).toString(16)}${Math.random().toString(16).slice(2, 7)}`;

export function createDemoApi(): SocApi {
  const alerts: Alert[] = [];
  const traces: Record<string, Trace[]> = {};
  const actions: Action[] = [];
  const blocks: Block[] = [];
  const audit: AuditEntry[] = [];
  const listeners = new Set<(e: StreamEvent) => void>();
  const emit = (e: StreamEvent) => listeners.forEach((l) => l(e));
  let auditSeq = 1;

  function materialise(s: Scenario, ageMin: number, live: boolean): Alert {
    const alert: Alert = { ...s.alert, id: id("ALR"), created_at: iso(ageMin), status: live ? "new" : "triaging", simulated: true, verdict: null };
    alerts.unshift(alert);
    traces[alert.id] = [];
    return alert;
  }

  function finish(alert: Alert, s: Scenario) {
    const proposed: Action[] = s.actions.map((a) => ({
      id: id("ACT"), alert_id: alert.id, created_at: iso(), type: a.type, target: a.target, provider: "mock",
      reason: a.reason, status: "pending",
    }));
    actions.unshift(...proposed);
    const refs = s.steps.filter((x) => x[0] === "threat_intel" && x[1] === "tool").flatMap((x) => (x[3] as { title: string; score: number }[]) ?? []);
    const matches = s.steps.filter((x) => x[0] === "threat_intel" && x[1] === "result").flatMap((x) => (Array.isArray(x[3]) ? (x[3] as never[]) : []));
    alert.verdict = {
      ...s.verdict,
      reasoning: s.steps.filter((x) => x[0] === "triage" && x[1] === "thought").map((x) => x[2]),
      intel_refs: refs.map((r) => ({ ...r, source: "reference" })),
      ioc_matches: matches,
    };
    alert.severity = s.verdict.severity;
    alert.status = s.verdict.verdict === "benign" ? "false_positive" : proposed.length ? "awaiting_approval" : "triaged";
    const extra: Step[] = proposed.map((a) => ["response", "decision", `Proposed ${a.type.replace(/_/g, " ")} → ${a.target} via mock (awaiting approval)`]);
    if (!proposed.length && s.verdict.verdict !== "benign") extra.push(["response", "result", "No containment actions proposed"]);
    extra.push(["reporter", "result", `Case updated → ${alert.status.replace(/_/g, " ")}. ${s.verdict.summary}`]);
    return { proposed, extra };
  }

  function pushTrace(alert: Alert, step: Step) {
    const t: Trace = { id: seq++, alert_id: alert.id, ts: iso(), agent: step[0], kind: step[1], message: step[2], data: step[3] };
    traces[alert.id].push(t);
    emit({ type: "trace", payload: t });
  }

  // Seed: three finished cases so the screens are not empty.
  [[0, 42], [3, 95], [1, 20]].forEach(([i, age]) => {
    const s = SCENARIOS[i];
    const a = materialise(s, age, false);
    s.steps.forEach((st) => traces[a.id].push({ id: seq++, alert_id: a.id, ts: a.created_at, agent: st[0], kind: st[1], message: st[2], data: st[3] }));
    const { extra } = finish(a, s);
    extra.forEach((st) => traces[a.id].push({ id: seq++, alert_id: a.id, ts: a.created_at, agent: st[0], kind: st[1], message: st[2] }));
  });
  blocks.push({ target: "203.0.113.9", kind: "ip", provider: "mock", created_at: iso(300) });

  async function runLive(alert: Alert, s: Scenario) {
    await sleep(500);
    alert.status = "triaging";
    emit({ type: "alert", payload: { ...alert } });
    for (const step of s.steps) {
      await sleep(step[0] === "triage" ? 1100 : 650);
      pushTrace(alert, step);
    }
    await sleep(600);
    const { proposed, extra } = finish(alert, s);
    for (const st of extra) {
      await sleep(450);
      pushTrace(alert, st);
    }
    proposed.forEach((a) => emit({ type: "action", payload: a }));
    emit({ type: "alert", payload: { ...alert } });
  }

  let nextScenario = 2;
  const api: SocApi = {
    demo: true,
    needsLogin: async () => false,
    login: async () => {},
    logout: () => {},
    health: async () => ({
      status: "ok", auth_required: false, demo_mode: true,
      llm: { provider: "demo", ok: true, label: "Demo data · no backend" },
      vector_store: "milvus-lite · hash embeddings", intel_records: 13,
      firewall_provider: "mock", identity_provider: "mock", auto_approve: false,
    }),
    stats: async () => {
      const bySev: Record<string, number> = {};
      const byStatus: Record<string, number> = {};
      alerts.forEach((a) => {
        bySev[a.severity] = (bySev[a.severity] || 0) + 1;
        byStatus[a.status] = (byStatus[a.status] || 0) + 1;
      });
      const hours = Array.from({ length: 12 }, (_, i) => ({ hour: String(i), n: [2, 1, 0, 3, 5, 2, 1, 4, 6, 3, 2, 0][i] + (i === 11 ? alerts.length : 0) }));
      return {
        alerts_total: alerts.length, alerts_by_severity: bySev, alerts_by_status: byStatus, alerts_by_hour: hours,
        pending_actions: actions.filter((a) => a.status === "pending").length, blocked_targets: blocks.length, intel_records: 13,
      };
    },
    alerts: async () => alerts.map((a) => ({ ...a })),
    alert: async (aid) => {
      const alert = alerts.find((a) => a.id === aid);
      if (!alert) throw new Error("Alert not found");
      return { alert: { ...alert }, traces: [...(traces[aid] || [])], actions: actions.filter((a) => a.alert_id === aid) };
    },
    rerun: async () => {},
    simulate: async (scenario) => {
      const idx = scenario ?? nextScenario++ % SCENARIOS.length;
      const s = SCENARIOS[idx % SCENARIOS.length];
      const alert = materialise(s, 0, true);
      emit({ type: "alert", payload: { ...alert } });
      void runLive(alert, s);
      return { ...alert };
    },
    actions: async () => actions.map((a) => ({ ...a })),
    decide: async (aid, approve) => {
      const a = actions.find((x) => x.id === aid);
      if (!a) throw new Error("Action not found");
      if (a.status !== "pending") throw new Error(`Action is already ${a.status}`);
      a.status = approve ? "executed" : "rejected";
      a.decided_by = "analyst";
      a.decided_at = iso();
      a.result = approve ? { message: `${a.target} handled by the simulated ${a.type.includes("ip") ? "firewall" : "identity provider"}` } : null;
      if (approve && a.type === "block_ip") blocks.unshift({ target: a.target, kind: "ip", provider: "mock", action_id: a.id, created_at: iso() });
      audit.unshift({ id: auditSeq++, ts: iso(), actor: "analyst", event: approve ? "approve_action" : "reject_action", detail: { type: a.type, target: a.target } });
      const alert = alerts.find((x) => x.id === a.alert_id);
      if (alert) {
        pushTrace(alert, ["analyst", "decision", `analyst ${approve ? "approved" : "rejected"} ${a.type} → ${a.target}`]);
        if (approve) pushTrace(alert, ["soar", "result", `Executed ${a.type} → ${a.target}: ${a.result?.message}`]);
        if (!actions.some((x) => x.alert_id === alert.id && x.status === "pending")) {
          alert.status = "resolved";
          emit({ type: "alert", payload: { ...alert } });
        }
      }
      emit({ type: "action", payload: { ...a } });
      return { ...a };
    },
    blocklist: async () => [...blocks],
    unblock: async (t) => {
      const i = blocks.findIndex((b) => b.target === t);
      if (i >= 0) blocks.splice(i, 1);
      audit.unshift({ id: auditSeq++, ts: iso(), actor: "analyst", event: "execute_action", detail: { message: `Removed ${t} from the blocklist` } });
    },
    searchIntel: async (q) => {
      const words = q.toLowerCase().split(/\W+/).filter(Boolean);
      const scored = INTEL.map((r) => {
        const hay = `${r.title} ${r.text} ${r.value}`.toLowerCase();
        const hits = words.filter((w) => hay.includes(w)).length;
        return { ...r, score: Math.round((hits / Math.max(words.length, 1)) * 100) / 100 };
      }).filter((r) => r.score > 0).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
      return { exact: INTEL.filter((r) => r.value === q.trim()), semantic: scored.slice(0, 6) };
    },
    importIntel: async (_f, content) => ({ imported: Math.max(0, content.trim().split("\n").length - 1) }),
    audit: async () => [...audit],
    subscribe(handler) {
      listeners.add(handler);
      setTimeout(() => handler({ type: "connection", payload: { connected: true } }), 50);
      return () => listeners.delete(handler);
    },
  };
  return api;
}
