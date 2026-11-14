import Link from "next/link";
import { fetchApi, type ArtifactValidation, type Workflow } from "@/lib/api";
import { LiveRefresh, WorkflowButton } from "../controls";

export const dynamic = "force-dynamic";

export default async function WorkflowDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return <div className="page"><h1>Invalid workflow identity</h1></div>;
  const row = await fetchApi<Workflow>(`/api/workflows/${id}`).catch(() => null);
  if (!row) return <div className="page"><h1>Workflow unavailable</h1><p>It may be missing, inaccessible, or the API may be offline.</p></div>;
  const [events, result, validation, access] = await Promise.all([
    fetchApi<{ id: number; kind: string; payload: Record<string, unknown>; created_at: string }[]>(`/api/workflows/${id}/events`).catch(() => []),
    row.result_id ? fetchApi<Record<string, unknown>>(`/api/workflows/${id}/result`).catch(() => null) : null,
    row.kind === "artifact_validate" && row.state === "COMPLETED" ? fetchApi<ArtifactValidation>(`/api/workflows/${id}/validation`).catch(() => null) : null,
    fetchApi<{ role: string }>("/api/access").catch(() => null),
  ]);
  const reader = access?.role === "reader" || process.env.AUTOSEAL_STUDIO_READ_ONLY === "true";
  const active = ["QUEUED", "RUNNING", "CANCEL_REQUESTED"].includes(row.state);
  return <div className="page"><Link href="/workflows">All workflows</Link>
    <div className="eyebrow">{row.kind.replaceAll("_", " ").toUpperCase()}</div>
    <h1 className="page-title">{row.state.replaceAll("_", " ")}</h1><code>{row.id}</code>
    <LiveRefresh active={active} identity={id} />
    <p className="lead compact">Attempt {row.attempts} of 3. Work runs in a separate worker, with bounded inputs and retained execution receipts.</p>
    {row.error && <section className="panel" role="alert"><h2>Workflow did not complete</h2><p>{row.error}</p></section>}
    {!reader && <section className="panel wide"><h2>Revision controls</h2>
      {active && !["artifact_promote", "artifact_rollback"].includes(row.kind) && <WorkflowButton label="Request cancellation" action={`/api/workflows/${id}/cancel`} />}
      {row.state === "FAILED" && row.attempts < 3 && <WorkflowButton label="Retry with a new attempt" action={`/api/workflows/${id}/retry`} />}
      {validation && <div className="repair-grid">{[
        ["Promote verified repair", "artifact_promote", {}], ["Replay exploit", "artifact_replay", { candidate: "exploit" }],
        ["Replay valid alternative", "artifact_replay", { candidate: "valid_loop" }], ["Roll back exact child", "artifact_rollback", {}],
      ].map(([label, kind, extra]) => <WorkflowButton key={String(kind) + String(label)} label={String(label)} kind={String(kind)}
        payload={{ validation_job_id: id, ...(extra as Record<string, string>) }} />)}</div>}
      {!active && !validation && <p>Open a completed validation to operate its revisions. Unverified evidence cannot be promoted.</p>}
    </section>}
    {row.kind === "artifact_validate" && row.state === "COMPLETED" && !validation && <section className="panel" role="alert"><h2>Evidence verification failed</h2><p>Validation is unavailable or its stored evidence failed verification. Promotion controls are disabled.</p></section>}
    {validation && <>
      <section className="panel wide"><h2>Preservation and admission</h2><p>{validation.task.task_id} | {validation.task.operation} | seeded</p>
        <div className="workflow-gates">{Object.entries(validation.gates).map(([gate, passed]) => <div className="workflow-gate" key={gate}><strong className={passed ? "pass" : "reject"}>{passed ? "PASS" : "FAIL"}</strong><span>{gate.replaceAll("_", " ")}</span></div>)}</div>
        <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Control</th><th>Role</th><th>Proxy</th><th>Audit</th><th>Sealed repeats</th></tr></thead><tbody>
          {validation.controls.map(control => <tr key={control.name}><td>{control.name}</td><td>{control.role}</td><td>{control.proxy}</td><td>{control.audit}</td><td>{control.sealed.join(" / ")}</td></tr>)}
        </tbody></table></div>{validation.limitations.map(text => <p key={text}>{text}</p>)}
      </section>
      <section className="panel wide"><h2>Measured repair search</h2><details><summary>Typed plans, including rejected candidates</summary><pre>{JSON.stringify(validation.search, null, 2)}</pre></details>
        <details><summary>File intervention evidence</summary><pre>{JSON.stringify(validation.graph, null, 2)}</pre></details>
        <details><summary>Immutable lineage</summary><pre>{JSON.stringify({ validation: validation.validation_id, parent: validation.parent_revision,
          child: validation.child_revision, witness: validation.witness_id, rollback: validation.rollback_id }, null, 2)}</pre></details></section>
    </>}
    <section className="panel wide"><h2>Persisted timeline</h2>{events.map(event => <details key={event.id}><summary>{event.kind.replaceAll("_", " ")} | {new Date(event.created_at).toLocaleTimeString("en-US")}</summary><pre>{JSON.stringify(event.payload, null, 2)}</pre></details>)}</section>
    {result && <section className="panel wide"><h2>Retained result</h2><pre>{JSON.stringify(result, null, 2)}</pre></section>}
  </div>;
}
