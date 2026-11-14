"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export function LiveRefresh({ active, identity }: { active: boolean; identity?: string }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    if (!identity) {
      const timer = setInterval(() => router.refresh(), 2500);
      return () => clearInterval(timer);
    }
    const events = new EventSource(`/api/workflows/${identity}/stream`);
    let refresh: ReturnType<typeof setTimeout> | undefined;
    let fallback: ReturnType<typeof setInterval> | undefined;
    events.addEventListener("workflow", event => {
      const row = JSON.parse((event as MessageEvent).data) as { kind: string };
      if (!refresh) refresh = setTimeout(() => { refresh = undefined; router.refresh(); }, 500);
      if (["COMPLETED", "FAILED", "CANCELLED"].includes(row.kind)) events.close();
    });
    events.onerror = () => {
      events.close();
      fallback = setInterval(() => router.refresh(), 5000);
    };
    return () => { events.close(); if (refresh) clearTimeout(refresh); if (fallback) clearInterval(fallback); };
  }, [active, identity, router]);
  return null;
}

export function WorkflowButton({ label, kind, payload, action, disabled = false }: {
  label: string; kind?: string; payload?: Record<string, string>; action?: string; disabled?: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  async function submit() {
    setBusy(true); setError("");
    try {
      const response = await fetch(action ?? "/api/workflows", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(action ? {} : { kind, payload, idempotency_key: crypto.randomUUID() }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? result.error ?? "Request failed");
      router.push(`/workflows/${result.id}`); router.refresh();
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Request failed"); }
    finally { setBusy(false); }
  }
  return <span><button className="button primary" disabled={busy || disabled} onClick={submit}>{busy ? "Submitting..." : label}</button>
    {error && <span role="alert" className="muted"> {error}</span>}</span>;
}
