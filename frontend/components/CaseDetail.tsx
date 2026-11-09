"use client";
import { useEffect, useMemo, useState } from "react";
import type { Action, Alert, SocApi, Trace } from "@/lib/types";
import { ACTION_LABEL, timeAgo } from "@/lib/useSoc";
import { TraceLanes } from "./TraceLanes";
import { Mono, SevTag, StatusTag } from "./ui";

interface Props {
  api: SocApi;
  alertId: string;
  alertFromList?: Alert;
  actionsFromList: Action[];
  onTrace: (fn: (t: Trace) => void) => () => void;
}

export function CaseDetail({ api, alertId, alertFromList, actionsFromList, onTrace }: Props) {
  const [alert, setAlert] = useState<Alert | null>(null);
  const [traces, setTraces] = useState<Trace[]>([]);
  const [fresh, setFresh] = useState<Set<number | undefined>>(new Set());
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setTraces([]);
    setFresh(new Set());
    api
      .alert(alertId)
      .then((d) => {
        if (cancelled) return;
        setAlert(d.alert);
        setTraces(d.traces);
        setError(null);
      })
      .catch((e) => !cancelled && setError(String(e.message ?? e)));
    const off = onTrace((t) => {
      if (t.alert_id !== alertId) return;
      setTraces((list) => (list.some((x) => x.id === t.id) ? list : [...list, t]));
      setFresh((s) => new Set(s).add(t.id));
    });
    return () => {
      cancelled = true;
      off();
    };
  }, [api, alertId, onTrace]);

  // Keep header/verdict in sync with live list updates.
  useEffect(() => {
    if (alertFromList && alert && alertFromList.updated_at !== alert.updated_at) setAlert({ ...alert, ...alertFromList });
    if (alertFromList && alert && alertFromList.status !== alert.status) setAlert({ ...alert, ...alertFromList });
  }, [alertFromList]); // eslint-disable-line react-hooks/exhaustive-deps

  const a = alert ?? alertFromList ?? null;
  const actions = useMemo(() => actionsFromList.filter((x) => x.alert_id === alertId), [actionsFromList, alertId]);
  if (error) return <div className="case-error">Couldn’t load this case: {error}</div>;
  if (!a) return <div className="case-loading">Loading case…</div>;

  const v = a.verdict;
  const live = a.status === "new" || a.status === "triaging";
  const indicators: [string, string | null | undefined][] = [
    ["Source", a.src_ip],
    ["Destination", a.dst_ip],
    ["User", a.username],
  ];

  return (
    <article className="case">
      <header className="case-head">
        <div className="case-tags">
          <SevTag severity={a.severity} />
          <StatusTag status={a.status} />
          {a.simulated && <span className="sim">Simulated</span>}
        </div>
        <h1>{a.title}</h1>
        <p className="case-desc">{a.description}</p>
        <dl className="case-meta">
          <div>
            <dt>Case</dt>
            <dd><Mono>{a.id}</Mono></dd>
          </div>
          <div>
            <dt>From</dt>
            <dd>{a.source}</dd>
          </div>
          <div>
            <dt>Opened</dt>
            <dd>{timeAgo(a.created_at)}</dd>
          </div>
          {indicators.filter(([, val]) => val).map(([k, val]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd><Mono>{val}</Mono></dd>
            </div>
          ))}
        </dl>
      </header>

      {v && (
        <section className={`verdict verdict-${v.verdict}`}>
          <div className="verdict-main">
            <p className="verdict-word">{v.verdict}</p>
            <div className="confidence" aria-label={`Confidence ${Math.round(v.confidence * 100)}%`}>
              <span style={{ width: `${Math.round(v.confidence * 100)}%` }} />
            </div>
            <p className="verdict-conf">{Math.round(v.confidence * 100)}% confident</p>
          </div>
          <div className="verdict-text">
            <p>{v.summary}</p>
            <div className="verdict-foot">
              {v.mitre?.map((t) => (
                <a key={t} className="mitre mono" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer">
                  {t}
                </a>
              ))}
              {v.engine && <span className="engine">Analysed by {v.engine}</span>}
            </div>
          </div>
        </section>
      )}

      {actions.length > 0 && <ActionList api={api} actions={actions} />}

      <section className="case-trace">
        <h2>How the agents reached this</h2>
        {traces.length === 0 && !live ? (
          <p className="muted">No reasoning steps were recorded for this case.</p>
        ) : (
          <TraceLanes traces={traces} live={live} freshIds={fresh} />
        )}
      </section>

      {v?.intel_refs && v.intel_refs.length > 0 && (
        <section className="case-refs">
          <h2>Intel the agents used</h2>
          <ul>
            {v.intel_refs.map((r, i) => (
              <li key={i}>
                <span>{r.title}</span>
                <span className="mono muted">{r.score?.toFixed(2)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </article>
  );
}

const PROVIDER_NAME: Record<string, string> = { aws_waf: "AWS WAF", aws_iam: "AWS IAM", okta: "Okta", script: "your firewall script" };
function providerName(a: Action): string {
  if (a.provider === "mock") return a.type.endsWith("_ip") ? "simulated firewall" : "simulated identity provider";
  return PROVIDER_NAME[a.provider] ?? a.provider;
}

export function ActionList({ api, actions, showCase = false, onOpenCase }: { api: SocApi; actions: Action[]; showCase?: boolean; onOpenCase?: (id: string) => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function decide(a: Action, approve: boolean) {
    setBusy(a.id);
    setErr(null);
    try {
      await api.decide(a.id, approve);
      setConfirming(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="actions">
      <h2>Proposed changes</h2>
      {err && <p className="inline-error">{err}</p>}
      <ul>
        {actions.map((a) => (
          <li key={a.id} className={`action action-${a.status}`}>
            <div className="action-what">
              <p className="action-title">
                {ACTION_LABEL[a.type] ?? a.type} <Mono>{a.target}</Mono>
              </p>
              <p className="action-why">{a.reason}</p>
              <p className="action-meta">
                Runs on <strong>{providerName(a)}</strong>
                {showCase && a.alert_id && (
                  <>
                    {" "}for{" "}
                    <button className="link" onClick={() => onOpenCase?.(a.alert_id!)}>
                      case {a.alert_id}
                    </button>
                  </>
                )}
                {a.result?.message && <> · {a.result.message}</>}
                {a.result?.error && <span className="inline-error"> · {a.result.error}</span>}
              </p>
            </div>
            <div className="action-do">
              {a.status === "pending" ? (
                confirming === a.id ? (
                  <>
                    <button className="btn danger" disabled={busy === a.id} onClick={() => decide(a, true)}>
                      {busy === a.id ? "Running…" : `Yes, ${(ACTION_LABEL[a.type] ?? a.type).toLowerCase()}`}
                    </button>
                    <button className="btn ghost" onClick={() => setConfirming(null)}>Cancel</button>
                  </>
                ) : (
                  <>
                    <button className="btn primary" onClick={() => setConfirming(a.id)}>Approve</button>
                    <button className="btn ghost" disabled={busy === a.id} onClick={() => decide(a, false)}>Reject</button>
                  </>
                )
              ) : (
                <span className={`done done-${a.status}`}>
                  {a.status === "executed" ? "Done" : a.status === "rejected" ? "Rejected" : a.status === "failed" ? "Failed" : a.status}
                  {a.decided_by && <small> by {a.decided_by}</small>}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
