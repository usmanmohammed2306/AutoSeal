import Link from "next/link";
import { fetchApi, type Run, type RunEvent, type RunEvidence } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function RunDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let run: Run | null = null;
  let events: RunEvent[] = [];
  let evidence: RunEvidence | null = null;
  let evidenceError = false;
  try {
    run = await fetchApi<Run>(`/api/runs/${encodeURIComponent(id)}`);
    events = await fetchApi<RunEvent[]>(`/api/runs/${encodeURIComponent(id)}/events`);
  } catch { /* The visible error state below is deliberate. */ }
  if (run?.manifest_id) {
    try { evidence = await fetchApi<RunEvidence>(`/api/runs/${encodeURIComponent(id)}/evidence`); }
    catch { evidenceError = true; }
  }
  if (!run) return <div className="page"><div className="eyebrow">RUN NOT AVAILABLE</div><h1 className="page-title">No record found</h1><Link className="text-link" href="/runs">Back to runs ↗</Link></div>;

  return <div className="page"><Link href="/runs" className="back-link">← All runs</Link><div className="eyebrow">RUN DETAIL / {run.id.slice(0, 8)}</div><div className="detail-title"><div><h1 className="page-title">{run.candidate}</h1><p className="lead compact">The candidate, evaluator, and process evidence behind this verdict.</p></div><span className={`status large status-${run.state.toLowerCase()}`}>{run.classification ?? run.state}</span></div>
    {run.state === "QUEUED" || run.state === "RUNNING" ? <div className="notice">This run is {run.state.toLowerCase()}. Start or keep the worker running, then refresh this page.</div> : null}
    {run.error && <div className="notice error">Run failure: {run.error}</div>}
    {evidence?.model && <section className="panel wide"><span className="section-kicker">REAL MODEL TOOL RUN</span><h2>{evidence.model.served_model}</h2><p className="lead compact">Sol supplies trusted inference. Candidate tools and evaluators execute in local Docker. Importing this record does not promote a repair.</p><dl><dt>Stop reason</dt><dd>{evidence.model.agent_stopped_reason}</dd><dt>Complete evidence</dt><dd>{evidence.model.complete_evidence ? "Yes" : "No"}</dd><dt>Tool policy</dt><dd>{evidence.model.tool_policy}</dd><dt>Token usage</dt><dd>{evidence.model.prompt_tokens} input, {evidence.model.completion_tokens} output</dd><dt>Model revision</dt><dd>{evidence.model.model_revision}</dd><dt>Model run</dt><dd>{evidence.model_run_id}</dd></dl><h3>Observed tool actions</h3><ol>{evidence.model.tool_actions.map((action, index) => <li key={index}>{action.kind}: {action.path ?? action.command?.join(" ")}</li>)}</ol><h3>Model summary, not a verifier verdict</h3><pre>{evidence.model.final_message}</pre></section>}
    {evidenceError && <div className="notice error">This run has a manifest identity, but its evidence blob is unavailable or failed verification in the configured store. The verdict cannot be inspected until that storage mismatch is resolved.</div>}
    <div className="detail-grid"><section className="panel"><span className="section-kicker">EVALUATOR COMPARISON</span><h2>Two independent verdicts</h2>{evidence ? <div className="comparison"><EvidenceCard title="Vulnerable proxy" evidence={evidence.proxy} /><EvidenceCard title="Independent audit" evidence={evidence.audit} /></div> : <p className="empty">{evidenceError ? "Evidence is unavailable for this stored run." : "Evidence will appear after the worker completes."}</p>}</section><section className="panel"><span className="section-kicker">EVENT LOG</span><h2>Run timeline</h2><div className="timeline">{events.map((event) => <div className="timeline-item" key={event.id}><span className="timeline-dot" /><div><strong>{event.kind}</strong><small>{new Date(event.created_at).toLocaleString()}</small></div></div>)}</div></section></div>
    {evidence && <><section className="panel wide identity-panel"><div><span className="section-kicker">IMMUTABLE INPUT</span><h2>Evidence identities</h2></div><dl><dt>Candidate</dt><dd>{evidence.candidate_identity}</dd><dt>Proxy image</dt><dd>{evidence.proxy.image_identity}</dd><dt>Audit image</dt><dd>{evidence.audit.image_identity}</dd><dt>Manifest</dt><dd>{run.manifest_id}</dd></dl></section><section className="panel wide"><span className="section-kicker">RAW PROCESS EVIDENCE</span><h2>Verifier output</h2><div className="output-grid"><div><h3>Proxy stdout</h3><pre>{evidence.proxy.process.stdout || "No stdout"}</pre></div><div><h3>Audit stdout</h3><pre>{evidence.audit.process.stdout || "No stdout"}</pre></div></div></section></>}
  </div>;
}

function EvidenceCard({ title, evidence }: { title: string; evidence: RunEvidence["proxy"] }) {
  return <div className={`evidence-card ${evidence.verdict.toLowerCase()}`}><div className="evidence-card-top"><span>{title}</span><strong>{evidence.verdict}</strong></div><div className="count-row"><span><b>{evidence.counts.passed}</b> passed</span><span><b>{evidence.counts.failed}</b> failed</span><span><b>{evidence.counts.skipped}</b> skipped</span></div><small>{evidence.copied_files.join(" · ")}</small></div>;
}
