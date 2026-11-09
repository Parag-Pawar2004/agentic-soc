"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Action, Alert, Health, SocApi, Stats, StreamEvent, Trace } from "./types";

export interface SocData {
  alerts: Alert[];
  actions: Action[];
  stats: Stats | null;
  health: Health | null;
  connected: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  onTrace: (fn: (t: Trace) => void) => () => void;
}

function upsert<T extends { id: string }>(list: T[], item: T): T[] {
  const i = list.findIndex((x) => x.id === item.id);
  if (i === -1) return [item, ...list];
  const copy = list.slice();
  copy[i] = { ...copy[i], ...item };
  return copy;
}

export function useSoc(api: SocApi, enabled: boolean): SocData {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const traceListeners = useRef(new Set<(t: Trace) => void>());
  const statsTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refreshStats = useCallback(() => {
    if (statsTimer.current) clearTimeout(statsTimer.current);
    statsTimer.current = setTimeout(() => {
      api.stats().then(setStats).catch(() => {});
    }, 300);
  }, [api]);

  const refresh = useCallback(async () => {
    try {
      const [a, ac, s, h] = await Promise.all([api.alerts(), api.actions(), api.stats(), api.health()]);
      setAlerts(a);
      setActions(ac);
      setStats(s);
      setHealth(h);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);

  useEffect(() => {
    if (!enabled) return;
    void refresh();
    const healthTimer = setInterval(() => api.health().then(setHealth).catch(() => {}), 30000);
    const unsub = api.subscribe((e: StreamEvent) => {
      switch (e.type) {
        case "connection":
          setConnected(e.payload.connected);
          if (e.payload.connected) void refresh();
          break;
        case "alert":
          setAlerts((list) => upsert(list, e.payload));
          refreshStats();
          break;
        case "action":
          setActions((list) => upsert(list, e.payload));
          refreshStats();
          break;
        case "trace":
          traceListeners.current.forEach((fn) => fn(e.payload));
          break;
      }
    });
    return () => {
      unsub();
      clearInterval(healthTimer);
    };
  }, [api, enabled, refresh, refreshStats]);

  const onTrace = useCallback((fn: (t: Trace) => void) => {
    traceListeners.current.add(fn);
    return () => {
      traceListeners.current.delete(fn);
    };
  }, []);

  return { alerts, actions, stats, health, connected, error, refresh, onTrace };
}

export function timeAgo(ts: string): string {
  const d = new Date(ts).getTime();
  if (Number.isNaN(d)) return ts;
  const s = Math.max(0, Math.round((Date.now() - d) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const STATUS_LABEL: Record<string, string> = {
  new: "New",
  triaging: "Agents working",
  awaiting_approval: "Needs approval",
  triaged: "Triaged",
  resolved: "Contained",
  false_positive: "False positive",
  error: "Pipeline error",
};

export const ACTION_LABEL: Record<string, string> = {
  block_ip: "Block IP",
  unblock_ip: "Unblock IP",
  suspend_user: "Suspend user",
  revoke_sessions: "Sign user out everywhere",
  disable_access_keys: "Disable cloud access keys",
};
