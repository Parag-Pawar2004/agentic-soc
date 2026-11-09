"use client";
import { useEffect, useMemo, useState } from "react";
import { getApi } from "@/lib/api";
import { useSoc } from "@/lib/useSoc";
import { CaseDetail } from "./CaseDetail";
import { Approvals, CaseList, Intel, Overview, ResponseLog, System } from "./Views";
import { Empty } from "./ui";

type View = "overview" | "cases" | "approvals" | "intel" | "response" | "system";

const NAV: { key: View; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "cases", label: "Cases" },
  { key: "approvals", label: "Approvals" },
  { key: "intel", label: "Threat intel" },
  { key: "response", label: "Blocklist & audit" },
  { key: "system", label: "Setup status" },
];

function Logo() {
  return (
    <svg viewBox="0 0 32 32" width="28" height="28" aria-hidden="true">
      <circle cx="16" cy="16" r="13" fill="none" stroke="currentColor" strokeOpacity=".35" strokeWidth="1.5" />
      <circle cx="16" cy="16" r="7.5" fill="none" stroke="currentColor" strokeOpacity=".6" strokeWidth="1.5" />
      <path d="M16 16 L27 9" stroke="var(--live)" strokeWidth="2" strokeLinecap="round" />
      <circle cx="22.5" cy="11.6" r="2" fill="var(--live)" />
    </svg>
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const api = getApi();
  const [u, setU] = useState("analyst");
  const [p, setP] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <main className="login">
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setErr(null);
          try {
            await api.login(u, p);
            onDone();
          } catch (ex) {
            setErr(ex instanceof Error ? ex.message : String(ex));
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="login-brand"><Logo /> Agentic SOC</div>
        <h1>Sign in to the workspace</h1>
        <label>
          Username
          <input value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" autoFocus />
        </label>
        {err && <p className="inline-error">{err}</p>}
        <button className="btn primary wide" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="muted small">The password is the ANALYST_PASSWORD you chose during setup. It’s stored in the .env file.</p>
      </form>
    </main>
  );
}

export default function App() {
  const api = useMemo(() => getApi(), []);
  const [auth, setAuth] = useState<"checking" | "login" | "ok" | "offline">("checking");
  const [authError, setAuthError] = useState<string | null>(null);
  const [view, setView] = useState<View>("overview");
  const [selected, setSelected] = useState<string | null>(null);
  const [simBusy, setSimBusy] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const soc = useSoc(api, auth === "ok");

  const checkAuth = () => {
    setAuth("checking");
    api
      .needsLogin()
      .then((need) => setAuth(need ? "login" : "ok"))
      .catch((e) => {
        setAuthError(e instanceof Error ? e.message : String(e));
        setAuth("offline");
      });
  };
  useEffect(checkAuth, [api]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selected && soc.alerts.length) setSelected(soc.alerts[0].id);
  }, [soc.alerts, selected]);

  const pendingCount = soc.actions.filter((a) => a.status === "pending").length;
  const attentionCount = soc.alerts.filter((a) => ["awaiting_approval", "triaging", "new", "error"].includes(a.status)).length;
  const actionVersion = soc.actions.filter((a) => a.status !== "pending").length;

  const openCase = (id: string) => {
    setSelected(id);
    setView("cases");
    setNavOpen(false);
  };

  async function simulate() {
    setSimBusy(true);
    try {
      const a = await api.simulate();
      openCase(a.id);
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      setSimBusy(false);
    }
  }

  if (auth === "checking") return <main className="boot"><Logo /> Connecting to the SOC backend…</main>;
  if (auth === "login") return <Login onDone={() => setAuth("ok")} />;
  if (auth === "offline")
    return (
      <main className="boot offline">
        <Logo />
        <h1>The backend isn’t answering</h1>
        <p>{authError}</p>
        <p className="muted">Start everything with <code className="mono">python3 setup_soc.py --start</code>, then try again.</p>
        <button className="btn primary" onClick={checkAuth}>Try again</button>
      </main>
    );

  const h = soc.health;
  return (
    <div className={`shell ${navOpen ? "nav-open" : ""}`}>
      <aside className="sidebar">
        <div className="brand"><Logo /> <span>Agentic SOC</span></div>
        <nav aria-label="Main">
          {NAV.map((n) => (
            <button key={n.key} className={view === n.key ? "active" : ""} aria-current={view === n.key ? "page" : undefined}
              onClick={() => { setView(n.key); setNavOpen(false); }}>
              {n.label}
              {n.key === "approvals" && pendingCount > 0 && <span className="badge">{pendingCount}</span>}
              {n.key === "cases" && attentionCount > 0 && <span className="badge quiet">{attentionCount}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          {api.demo ? <p className="demo-note">Demo data. Nothing here touches a real network.</p> : (
            <button className="link" onClick={() => { api.logout(); setAuth("login"); }}>Sign out</button>
          )}
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <button className="menu" aria-label="Open navigation" onClick={() => setNavOpen((o) => !o)}>☰</button>
          <h1 className="page-title">{NAV.find((n) => n.key === view)?.label}</h1>
          <div className="status-strip">
            <span className={`pill ${soc.connected ? "pill-live" : "pill-down"}`} title="Live stream of agent activity">
              <i /> {soc.connected ? "Live" : "Reconnecting"}
            </span>
            {h && (
              <>
                <span className={`pill ${h.llm.ok ? "" : "pill-warn"}`} title="Model used by the triage agent">{h.llm.label}</span>
                <span className="pill hide-sm" title="Where threat intel is stored">{h.vector_store}</span>
              </>
            )}
          </div>
          <button className="btn primary" onClick={() => void simulate()} disabled={simBusy}>
            {simBusy ? "Sending…" : "Simulate alert"}
          </button>
        </header>

        {soc.error && <div className="banner">Can’t refresh data: {soc.error}</div>}

        <main className={`content view-${view}`}>
          {view === "overview" && (
            <Overview api={api} stats={soc.stats} alerts={soc.alerts} actions={soc.actions} onOpenCase={openCase} onSimulate={() => void simulate()} />
          )}
          {view === "cases" && (
            <div className="cases">
              <CaseList alerts={soc.alerts} selected={selected} onSelect={setSelected} />
              <div className="case-pane">
                {selected ? (
                  <CaseDetail
                    key={selected}
                    api={api}
                    alertId={selected}
                    alertFromList={soc.alerts.find((a) => a.id === selected)}
                    actionsFromList={soc.actions}
                    onTrace={soc.onTrace}
                  />
                ) : (
                  <Empty title="Pick a case">Or press Simulate alert to watch the agents triage one live.</Empty>
                )}
              </div>
            </div>
          )}
          {view === "approvals" && <Approvals api={api} actions={soc.actions} onOpenCase={openCase} />}
          {view === "intel" && <Intel api={api} />}
          {view === "response" && <ResponseLog api={api} version={actionVersion} />}
          {view === "system" && <System health={h} />}
        </main>
      </div>
    </div>
  );
}
