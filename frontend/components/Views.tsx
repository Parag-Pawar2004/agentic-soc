"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Action, Alert, AuditEntry, Block, Health, IntelRecord, SocApi, Stats } from "@/lib/types";
import { timeAgo } from "@/lib/useSoc";
import { ActionList } from "./CaseDetail";
import { Empty, Mono, Panel, SevTag, StatusTag } from "./ui";

const SEVS = ["critical", "high", "medium", "low"] as const;

// ---------------------------------------------------------------- Overview
export function Overview({
  api, stats, alerts, actions, onOpenCase, onSimulate,
}: {
  api: SocApi; stats: Stats | null; alerts: Alert[]; actions: Action[];
  onOpenCase: (id: string) => void; onSimulate: () => void;
}) {
  const pending = actions.filter((a) => a.status === "pending");
  const open = alerts.filter((a) => !["resolved", "false_positive"].includes(a.status));
  const sevTotal = SEVS.reduce((n, s) => n + (stats?.alerts_by_severity?.[s] ?? 0), 0) || 1;
  const hours = stats?.alerts_by_hour ?? [];
  const maxHour = Math.max(1, ...hours.map((h) => h.n));

  return (
    <div className="overview">
      <div className="ov-lead">
        <div className="ov-decision">
          <p className="ov-count">{pending.length}</p>
          <p className="ov-count-label">
            {pending.length === 1 ? "change is" : "changes are"} waiting for your approval
          </p>
        </div>
        <dl className="ov-figures">
          <div><dt>Open cases</dt><dd>{open.length}</dd></div>
          <div><dt>Blocked right now</dt><dd>{stats?.blocked_targets ?? "–"}</dd></div>
          <div><dt>Intel in the RAG store</dt><dd>{stats?.intel_records ?? "–"}</dd></div>
          <div><dt>Cases all time</dt><dd>{stats?.alerts_total ?? "–"}</dd></div>
        </dl>
      </div>

      <div className="ov-grid">
        <Panel title="Waiting for you" className="ov-pending">
          {pending.length ? (
            <ActionList api={api} actions={pending.slice(0, 4)} showCase onOpenCase={onOpenCase} />
          ) : (
            <Empty title="Nothing needs approval">
              When the response agent proposes a firewall or account change, it appears here first.
              <button className="btn ghost" onClick={onSimulate}>Simulate an alert</button>
            </Empty>
          )}
        </Panel>

        <Panel title="Severity mix">
          <div className="sevbar" role="img" aria-label="Cases by severity">
            {SEVS.map((s) => {
              const n = stats?.alerts_by_severity?.[s] ?? 0;
              return n ? <span key={s} className={`seg seg-${s}`} style={{ flexGrow: n / sevTotal }} title={`${s}: ${n}`} /> : null;
            })}
          </div>
          <ul className="sevlegend">
            {SEVS.map((s) => (
              <li key={s}>
                <SevTag severity={s} />
                <span>{stats?.alerts_by_severity?.[s] ?? 0}</span>
              </li>
            ))}
          </ul>
          <h3 className="sub">Alerts per hour</h3>
          <div className="hours" role="img" aria-label="Alerts per hour, most recent on the right">
            {hours.length ? hours.map((h, i) => (
              <span key={i} style={{ height: `${Math.max(4, (h.n / maxHour) * 100)}%` }} title={`${h.n} alert(s)`} />
            )) : <span className="muted">No data yet</span>}
          </div>
        </Panel>

        <Panel title="Latest cases" className="ov-recent">
          {alerts.length ? (
            <ul className="mini-cases">
              {alerts.slice(0, 6).map((a) => (
                <li key={a.id}>
                  <button onClick={() => onOpenCase(a.id)}>
                    <SevTag severity={a.severity} />
                    <span className="mc-title">{a.title}</span>
                    <StatusTag status={a.status} />
                    <span className="mc-time">{timeAgo(a.created_at)}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No alerts yet">Send one from your SIEM, or simulate one to watch the agents work.</Empty>
          )}
        </Panel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- Case list
const FILTERS: { key: string; label: string; test: (a: Alert) => boolean }[] = [
  { key: "attention", label: "Needs you", test: (a) => ["awaiting_approval", "triaging", "new", "error", "triaged"].includes(a.status) },
  { key: "all", label: "All", test: () => true },
  { key: "closed", label: "Closed", test: (a) => ["resolved", "false_positive"].includes(a.status) },
];

export function CaseList({ alerts, selected, onSelect }: { alerts: Alert[]; selected: string | null; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const list = useMemo(() => {
    const f = FILTERS.find((x) => x.key === filter)!;
    const needle = q.trim().toLowerCase();
    return alerts.filter(f.test).filter((a) =>
      !needle || [a.title, a.src_ip, a.dst_ip, a.username, a.id].some((v) => v?.toLowerCase().includes(needle)));
  }, [alerts, filter, q]);

  return (
    <div className="caselist">
      <div className="caselist-tools">
        <div className="segmented" role="tablist">
          {FILTERS.map((f) => (
            <button key={f.key} role="tab" aria-selected={filter === f.key} onClick={() => setFilter(f.key)}>
              {f.label}
              <span>{alerts.filter(f.test).length}</span>
            </button>
          ))}
        </div>
        <input className="search" placeholder="Find by title, IP or user" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter cases" />
      </div>
      {list.length ? (
        <ul>
          {list.map((a) => (
            <li key={a.id}>
              <button className={`case-row ${selected === a.id ? "selected" : ""} sevline-${a.severity}`} onClick={() => onSelect(a.id)}>
                <span className="cr-top">
                  <SevTag severity={a.severity} />
                  <StatusTag status={a.status} />
                  <span className="cr-time">{timeAgo(a.created_at)}</span>
                </span>
                <span className="cr-title">{a.title}</span>
                <span className="cr-meta">
                  {a.source}
                  {a.src_ip && <> · <Mono>{a.src_ip}</Mono></>}
                  {a.username && <> · <Mono>{a.username}</Mono></>}
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <Empty title={q ? "No cases match that search" : "No cases here"} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Approvals
export function Approvals({ api, actions, onOpenCase }: { api: SocApi; actions: Action[]; onOpenCase: (id: string) => void }) {
  const pending = actions.filter((a) => a.status === "pending");
  const history = actions.filter((a) => a.status !== "pending");
  return (
    <div className="stack">
      <Panel title="Waiting for approval">
        {pending.length ? (
          <ActionList api={api} actions={pending} showCase onOpenCase={onOpenCase} />
        ) : (
          <Empty title="You're all caught up">Nothing runs on your firewall or identity provider until you approve it here.</Empty>
        )}
      </Panel>
      <Panel title="Decided">
        {history.length ? <ActionList api={api} actions={history.slice(0, 50)} showCase onOpenCase={onOpenCase} /> : <Empty title="No decisions yet" />}
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------- Threat intel
export function Intel({ api }: { api: SocApi }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ exact: IntelRecord[]; semantic: IntelRecord[] } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const examples = ["many failed ssh logins", "regular beacon to one external server", "203.0.113.45", "files being encrypted"];

  async function search(text = q) {
    if (text.trim().length < 2) return;
    setQ(text);
    setBusy(true);
    try {
      setRes(await api.searchIntel(text));
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onFile(f: File | undefined) {
    if (!f) return;
    setMsg(`Importing ${f.name}…`);
    try {
      const r = await api.importIntel(f.name, await f.text());
      setMsg(`Imported ${r.imported} record(s) from ${f.name}. They're searchable now and the agents will use them.`);
    } catch (e) {
      setMsg(`Import failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <div className="stack">
      <Panel title="Ask the intel store">
        <form className="intel-search" onSubmit={(e) => { e.preventDefault(); void search(); }}>
          <input className="search big" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Describe behaviour or paste an indicator" aria-label="Search threat intel" />
          <button className="btn primary" disabled={busy}>{busy ? "Searching…" : "Search"}</button>
        </form>
        <p className="examples">
          Try:{" "}
          {examples.map((e) => (
            <button key={e} className="chip" onClick={() => void search(e)}>{e}</button>
          ))}
        </p>
        {res && (
          <div className="intel-results">
            {res.exact.length > 0 && (
              <>
                <h3 className="sub">Exact indicator matches</h3>
                <IntelList items={res.exact} />
              </>
            )}
            <h3 className="sub">Closest passages (semantic search)</h3>
            {res.semantic.length ? <IntelList items={res.semantic} /> : <p className="muted">Nothing close enough. Try describing the behaviour in more words.</p>}
          </div>
        )}
      </Panel>
      <Panel title="Add your own intel">
        <p className="prose">
          Import a CSV or JSON file you have the right to use, such as your team's blocklist or notes from past incidents.
          Columns the importer understands: <Mono>value</Mono>, <Mono>title</Mono>, <Mono>description</Mono>, <Mono>tags</Mono>, <Mono>source</Mono>.
          Files dropped into <Mono>backend/data/intel_import/</Mono> are loaded on every start.
        </p>
        <label className="btn ghost file">
          Choose a file
          <input ref={fileRef} type="file" accept=".csv,.json" onChange={(e) => void onFile(e.target.files?.[0])} />
        </label>
        {msg && <p className="note" role="status">{msg}</p>}
      </Panel>
    </div>
  );
}

function IntelList({ items }: { items: IntelRecord[] }) {
  return (
    <ul className="intel-list">
      {items.map((r) => (
        <li key={r.id}>
          <div className="il-head">
            <strong>{r.title}</strong>
            {typeof r.score === "number" && <span className="mono muted">{r.score.toFixed(2)}</span>}
          </div>
          <p>{r.text}</p>
          <p className="il-meta">
            {r.source} · {r.kind}
            {r.tags?.length ? ` · ${r.tags.join(", ")}` : ""}
          </p>
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- Response log
export function ResponseLog({ api, version }: { api: SocApi; version: number }) {
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const load = () => {
    api.blocklist().then(setBlocks).catch((e) => setErr(String(e.message ?? e)));
    api.audit().then(setAudit).catch(() => {});
  };
  useEffect(load, [api, version]); // eslint-disable-line react-hooks/exhaustive-deps

  async function undo(t: string) {
    try {
      await api.unblock(t);
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="stack">
      <Panel title="Currently blocked">
        {err && <p className="inline-error">{err}</p>}
        {blocks.length ? (
          <table className="table">
            <thead><tr><th>Target</th><th>Where</th><th>Since</th><th /></tr></thead>
            <tbody>
              {blocks.map((b) => (
                <tr key={b.target}>
                  <td><Mono>{b.target}</Mono> {b.kind === "user" && <span className="muted">(account)</span>}</td>
                  <td>{b.provider === "mock" ? "Simulated firewall" : b.provider}</td>
                  <td>{timeAgo(b.created_at)}</td>
                  <td className="right"><button className="btn ghost small" onClick={() => void undo(b.target)}>Undo</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title="Nothing is blocked" />
        )}
      </Panel>
      <Panel title="Audit trail">
        {audit.length ? (
          <table className="table">
            <thead><tr><th>When</th><th>Who</th><th>What</th></tr></thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td>{timeAgo(a.ts)}</td>
                  <td>{a.actor}</td>
                  <td>
                    {a.event.replace(/_/g, " ")}{" "}
                    <span className="muted">{a.detail ? Object.values(a.detail).filter((v) => typeof v === "string").join(" · ") : ""}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title="No recorded decisions yet" />
        )}
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------- System
export function System({ health }: { health: Health | null }) {
  if (!health) return <Empty title="Checking the backend…" />;
  const rows: [string, string, boolean | null, string][] = [
    ["Reasoning model", health.llm.label, health.llm.ok, health.llm.ok ? "" : "Not reachable. Agents fall back to the heuristic analyst. Add OPENROUTER_API_KEY to .env, or start Ollama."],
    ["Vector store (RAG)", health.vector_store, true, `${health.intel_records} records indexed`],
    ["Firewall changes", health.firewall_provider === "mock" ? "Simulated firewall" : health.firewall_provider, null, "Set FIREWALL_PROVIDER=aws_waf or script in .env to act on a real firewall."],
    ["Account actions", health.identity_provider === "mock" ? "Simulated identity provider" : health.identity_provider, null, "Set IDENTITY_PROVIDER=okta or aws_iam in .env."],
    ["Approvals", health.auto_approve ? "Automatic (not recommended)" : "Every change needs a person", !health.auto_approve, ""],
    ["Sign-in", health.auth_required ? "Password required" : "Open (no ANALYST_PASSWORD set)", health.auth_required, ""],
  ];
  return (
    <Panel title="How this workspace is set up">
      <table className="table system">
        <tbody>
          {rows.map(([k, v, ok, note]) => (
            <tr key={k}>
              <th>{k}</th>
              <td>
                <span className={`dot ${ok === null ? "dot-neutral" : ok ? "dot-ok" : "dot-bad"}`} />
                {v}
                {note && <p className="muted small">{note}</p>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="prose muted">
        Change any of these in the <Mono>.env</Mono> file at the project root (or rerun <Mono>python3 setup_soc.py --configure</Mono>), then restart.
      </p>
    </Panel>
  );
}
