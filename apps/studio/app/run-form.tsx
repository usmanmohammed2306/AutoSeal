"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const candidates = ["exploit", "exploit_variant", "positive", "positive_alternative", "negative", "negative_alternative"];

export function NewRunForm() {
  const router = useRouter();
  const [candidate, setCandidate] = useState("exploit");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ candidate, idempotency_key: crypto.randomUUID() }) });
      if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
      const run = await response.json();
      router.push(`/runs/${run.id}`);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to submit run");
      setBusy(false);
    }
  }

  return <form onSubmit={submit} className="run-form"><label htmlFor="candidate">Candidate</label><select id="candidate" value={candidate} onChange={(event) => setCandidate(event.target.value)}>{candidates.map((name) => <option key={name} value={name}>{name}</option>)}</select><button className="button primary" type="submit" disabled={busy}>{busy ? "Submitting..." : "Queue run"}<span>↗</span></button>{error && <p role="alert" className="form-error">{error}</p>}</form>;
}
