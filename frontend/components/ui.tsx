"use client";
import type { ReactNode } from "react";
import type { Severity } from "@/lib/types";
import { STATUS_LABEL } from "@/lib/useSoc";

export function SevTag({ severity }: { severity: Severity | string }) {
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}

export function StatusTag({ status }: { status: string }) {
  return <span className={`status status-${status}`}>{STATUS_LABEL[status] ?? status}</span>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function Panel({ title, aside, children, className = "" }: { title?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || aside) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="mono">{children}</code>;
}
