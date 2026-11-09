"use client";
import { useEffect, useRef } from "react";
import type { Trace } from "@/lib/types";

// Each agent gets a rail. A step is a node on its agent's rail; when work hands
// off between agents the connector bends across to the next rail.
export const LANES = [
  { key: "supervisor", label: "Supervisor", hint: "Reads the alert and picks a playbook" },
  { key: "threat_intel", label: "Threat intel", hint: "Matches indicators and searches the RAG store" },
  { key: "triage", label: "Triage", hint: "Llama 3 reasoning and verdict" },
  { key: "response", label: "Response", hint: "Proposes containment and applies guardrails" },
  { key: "human", label: "You + SOAR", hint: "Your approvals and the changes that ran" },
];

export function laneOf(agent: string): number {
  if (agent === "analyst" || agent === "soar") return 4;
  if (agent === "reporter") return 3;
  const i = LANES.findIndex((l) => l.key === agent);
  return i === -1 ? 0 : i;
}

function DataPreview({ data }: { data: unknown }) {
  if (data == null) return null;
  if (Array.isArray(data)) {
    if (!data.length) return null;
    return (
      <ul className="trace-data">
        {data.slice(0, 4).map((d, i) => {
          const o = d as Record<string, unknown>;
          const label = String(o.title ?? o.indicator ?? JSON.stringify(d));
          return (
            <li key={i}>
              <span>{label}</span>
              {typeof o.score === "number" && <span className="trace-score mono">{o.score.toFixed(2)}</span>}
            </li>
          );
        })}
      </ul>
    );
  }
  if (typeof data === "object") {
    const entries = Object.entries(data as Record<string, unknown>).filter(
      ([k, v]) => k !== "action_id" && !(Array.isArray(v) && v.length === 0),
    );
    if (!entries.length) return null;
    return (
      <dl className="trace-kv">
        {entries.slice(0, 5).map(([k, v]) => (
          <div key={k}>
            <dt>{k.replace(/_/g, " ")}</dt>
            <dd className="mono">{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
          </div>
        ))}
      </dl>
    );
  }
  return null;
}

export function TraceLanes({ traces, live, freshIds }: { traces: Trace[]; live: boolean; freshIds: Set<number | undefined> }) {
  const end = useRef<HTMLDivElement>(null);
  const count = traces.length;
  useEffect(() => {
    if (live && count) end.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [count, live]);

  return (
    <div className="transit">
      <div className="transit-legend" aria-hidden="true">
        {LANES.map((l, i) => (
          <span key={l.key} className={`legend lane-${i}`} title={l.hint}>
            <i />
            {l.label}
          </span>
        ))}
      </div>
      <ol className="transit-steps" aria-label="Agent reasoning trace">
        {traces.map((t, row) => {
          const lane = laneOf(t.agent);
          const prev = row > 0 ? laneOf(traces[row - 1].agent) : lane;
          const time = new Date(t.ts);
          const lo = Math.min(prev, lane);
          const hi = Math.max(prev, lane);
          return (
            <li key={t.id ?? row} className={`tstep kind-${t.kind} ${freshIds.has(t.id) ? "fresh" : ""}`}>
              <time className="tstep-time mono">
                {Number.isNaN(time.getTime())
                  ? ""
                  : time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })}
              </time>
              <div className="rails" aria-hidden="true" style={{ ["--lane" as string]: lane }}>
                {LANES.map((_, i) => (
                  <span key={i} className={`rail lane-${i} ${i === lane ? "on" : ""}`} />
                ))}
                {prev !== lane && (
                  <span
                    className={`elbow lane-${lane}`}
                    style={{ ["--from" as string]: lo, ["--to" as string]: hi }}
                  />
                )}
                <span className={`node lane-${lane}`} />
              </div>
              <div className="tstep-body">
                <span className={`tstep-agent lane-${lane}`}>{LANES[lane].label}</span>
                <p>{t.message}</p>
                <DataPreview data={t.data} />
              </div>
            </li>
          );
        })}
        {live && (
          <li className="tstep pending" aria-live="polite">
            <span />
            <div className="rails" aria-hidden="true">
              {LANES.map((_, i) => (
                <span key={i} className={`rail lane-${i}`} />
              ))}
            </div>
            <div className="tstep-body">
              <p className="working">
                <span className="pulse" /> Agents are working on this case
              </p>
            </div>
          </li>
        )}
      </ol>
      <div ref={end} />
    </div>
  );
}
