export type Severity = "low" | "medium" | "high" | "critical";

export interface Verdict {
  verdict: "malicious" | "suspicious" | "benign";
  severity: Severity;
  confidence: number;
  summary: string;
  reasoning: string[];
  mitre: string[];
  engine?: string;
  domain?: string;
  ioc_matches?: { indicator: string; source: string; title: string }[];
  intel_refs?: { title: string; source: string; score: number }[];
}

export interface Alert {
  id: string;
  created_at: string;
  updated_at?: string;
  source: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  status: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  username?: string | null;
  simulated: boolean;
  raw: Record<string, unknown>;
  verdict?: Verdict | null;
}

export interface Trace {
  id?: number;
  alert_id: string;
  ts: string;
  agent: string;
  kind: "thought" | "tool" | "result" | "decision" | "error";
  message: string;
  data?: unknown;
}

export interface Action {
  id: string;
  alert_id: string | null;
  created_at: string;
  type: string;
  target: string;
  provider: string;
  reason: string;
  status: "pending" | "approved" | "rejected" | "executed" | "failed";
  decided_by?: string | null;
  decided_at?: string | null;
  result?: { message?: string; error?: string } | null;
}

export interface Health {
  status: string;
  auth_required: boolean;
  demo_mode: boolean;
  llm: { provider: string; ok: boolean; label: string };
  vector_store: string;
  intel_records: number;
  firewall_provider: string;
  identity_provider: string;
  auto_approve: boolean;
}

export interface Stats {
  alerts_total: number;
  alerts_by_severity: Partial<Record<Severity, number>>;
  alerts_by_status: Record<string, number>;
  alerts_by_hour: { hour: string; n: number }[];
  pending_actions: number;
  blocked_targets: number;
  intel_records: number;
}

export interface Block {
  target: string;
  kind: string;
  provider: string;
  action_id?: string | null;
  created_at: string;
}

export interface IntelRecord {
  id: string;
  source: string;
  kind: string;
  value: string;
  title: string;
  text: string;
  tags: string[];
  score?: number;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  event: string;
  detail?: Record<string, unknown> | null;
}

export type StreamEvent =
  | { type: "trace"; payload: Trace }
  | { type: "alert"; payload: Alert }
  | { type: "action"; payload: Action }
  | { type: "hello" | "ping"; payload: unknown }
  | { type: "connection"; payload: { connected: boolean } };

export interface SocApi {
  demo: boolean;
  needsLogin(): Promise<boolean>;
  login(username: string, password: string): Promise<void>;
  logout(): void;
  health(): Promise<Health>;
  stats(): Promise<Stats>;
  alerts(): Promise<Alert[]>;
  alert(id: string): Promise<{ alert: Alert; traces: Trace[]; actions: Action[] }>;
  rerun(id: string): Promise<void>;
  simulate(scenario?: number): Promise<Alert>;
  actions(): Promise<Action[]>;
  decide(id: string, approve: boolean): Promise<Action>;
  blocklist(): Promise<Block[]>;
  unblock(target: string): Promise<void>;
  searchIntel(q: string): Promise<{ exact: IntelRecord[]; semantic: IntelRecord[] }>;
  importIntel(filename: string, content: string): Promise<{ imported: number }>;
  audit(): Promise<AuditEntry[]>;
  subscribe(handler: (e: StreamEvent) => void): () => void;
}
