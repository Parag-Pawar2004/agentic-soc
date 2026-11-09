import type { SocApi, StreamEvent } from "./types";
import { createDemoApi } from "./demo";

// "same-origin" = the backend is behind the same host (Kubernetes ingress routes /api and /ws).
const RAW_API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_URL = RAW_API_URL === "same-origin" ? "" : RAW_API_URL.replace(/\/$/, "");
const wsBase = () => (API_URL || window.location.origin).replace(/^http/, "ws");
const DEMO = process.env.NEXT_PUBLIC_DEMO_MODE === "1";
const TOKEN_KEY = "soc.token";

function readToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function writeToken(token: string | null) {
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: token lives only in memory */
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function createHttpApi(): SocApi {
  let token: string | null = typeof window !== "undefined" ? readToken() : null;

  async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    let res: Response;
    try {
      res = await fetch(`${API_URL}${path}`, { ...init, headers: { ...headers, ...(init.headers as object) } });
    } catch {
      throw new ApiError(0, `Can't reach the backend at ${API_URL || window.location.origin}. Is it running?`);
    }
    if (!res.ok) {
      let detail = res.statusText;
      try {
        detail = (await res.json()).detail ?? detail;
      } catch {
        /* not JSON */
      }
      throw new ApiError(res.status, String(detail));
    }
    return res.json() as Promise<T>;
  }

  return {
    demo: false,
    async needsLogin() {
      const h = await req<{ auth_required: boolean }>("/api/health");
      if (!h.auth_required) {
        if (!token) {
          const r = await req<{ token: string }>("/api/auth/login", { method: "POST", body: JSON.stringify({}) });
          token = r.token;
          writeToken(token);
        }
        return false;
      }
      if (!token) return true;
      try {
        await req("/api/stats");
        return false;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return true;
        throw e;
      }
    },
    async login(username, password) {
      const r = await req<{ token: string }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      token = r.token;
      writeToken(token);
    },
    logout() {
      token = null;
      writeToken(null);
    },
    health: () => req("/api/health"),
    stats: () => req("/api/stats"),
    alerts: () => req("/api/alerts?limit=200"),
    alert: (id) => req(`/api/alerts/${encodeURIComponent(id)}`),
    rerun: (id) => req(`/api/alerts/${encodeURIComponent(id)}/rerun`, { method: "POST" }),
    simulate: (s) => req(`/api/simulate${s === undefined ? "" : `?scenario=${s}`}`, { method: "POST" }),
    actions: () => req("/api/actions"),
    decide: (id, approve) =>
      req(`/api/actions/${encodeURIComponent(id)}/${approve ? "approve" : "reject"}`, { method: "POST" }),
    blocklist: () => req("/api/blocklist"),
    unblock: (t) => req(`/api/blocklist/${encodeURIComponent(t)}`, { method: "DELETE" }),
    searchIntel: (q) => req(`/api/intel/search?q=${encodeURIComponent(q)}`),
    importIntel: (filename, content) =>
      req("/api/intel/import", { method: "POST", body: JSON.stringify({ filename, content }) }),
    audit: () => req("/api/audit"),
    subscribe(handler) {
      let ws: WebSocket | null = null;
      let closed = false;
      let retry = 1000;
      const connect = () => {
        if (closed) return;
        const url = `${wsBase()}/ws?token=${encodeURIComponent(token || "")}`;
        ws = new WebSocket(url);
        ws.onopen = () => {
          retry = 1000;
          handler({ type: "connection", payload: { connected: true } });
        };
        ws.onmessage = (m) => {
          try {
            handler(JSON.parse(m.data) as StreamEvent);
          } catch {
            /* ignore malformed frames */
          }
        };
        ws.onclose = () => {
          handler({ type: "connection", payload: { connected: false } });
          if (!closed) setTimeout(connect, retry);
          retry = Math.min(retry * 2, 15000);
        };
      };
      connect();
      return () => {
        closed = true;
        ws?.close();
      };
    },
  };
}

let instance: SocApi | null = null;
export function getApi(): SocApi {
  if (!instance) instance = DEMO ? createDemoApi() : createHttpApi();
  return instance;
}
