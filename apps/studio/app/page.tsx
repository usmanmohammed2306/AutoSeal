import Link from "next/link";
import { fetchApi, type Run } from "@/lib/api";
import { NewRunForm } from "./run-form";

export const dynamic = "force-dynamic";

export default async function Overview() {
  let runs: Run[] = [];
  let apiError = false;
  try {
    runs = await fetchApi<Run[]>("/api/runs?limit=50");
  } catch {
    apiError = true;
  }
  const complete = runs.filter((run) => run.state === "COMPLETED");
  const falseRewards = complete.filter((run) => run.classification === "FALSE_REWARD");
  const latest = runs.slice(0, 6);

  return (
    <div className="page">
      <div className="eyebrow">EVALUATOR INTEGRITY LAB</div>
      <div className="hero-grid">
        <div>
          <h1>Did the agent solve the task, <em>or just pass the test?</em></h1>
          <p className="lead">AutoSeal compares a vulnerable proxy with an independent audit, keeps the execution evidence, and makes every disagreement inspectable.</p>
          <div className="hero-actions"><Link href="/runs" className="button primary">Explore runs <span>↗</span></Link><span className="subtle">Current scope: reproducible fixture runs</span></div>
        </div>
        <div className="hero-visual" aria-label="Proxy and audit disagreement illustration">
          <div className="visual-title">ONE CANDIDATE. TWO VERDICTS.</div>
          <div className="flow-node">Candidate artifact <span>same identity</span></div>
          <div className="flow-split"><div className="flow-line" /><div className="flow-line" /></div>
          <div className="verdicts"><div className="verdict-card proxy">PROXY<span>PASS</span><small>7 tests skipped</small></div><div className="verdict-card audit">AUDIT<span>REJECT</span><small>3 tests failed</small></div></div>
          <div className="visual-footer">False reward detected in the local fixture</div>
        </div>
      </div>

      {apiError && <div className="notice">The API is not reachable. Start PostgreSQL, migrate, then run the API and worker to see live records.</div>}

      <section className="metrics" aria-label="Run metrics">
        <div className="metric"><span>Total runs</span><strong>{runs.length}</strong><small>Persisted requests</small></div>
        <div className="metric"><span>Completed</span><strong>{complete.length}</strong><small>Worker-produced evidence</small></div>
        <div className="metric accent"><span>False rewards</span><strong>{falseRewards.length}</strong><small>Proxy pass, audit reject</small></div>
      </section>

      <div className="section-grid">
        <section className="panel">
          <div className="panel-header"><div><span className="section-kicker">LIVE DATA</span><h2>Recent runs</h2></div><Link href="/runs" className="text-link">View all ↗</Link></div>
          {latest.length === 0 ? <p className="empty">No runs yet. Submit a checked-in candidate to create the first evidence record.</p> : (
            <div className="run-list">{latest.map((run) => <Link href={`/runs/${run.id}`} key={run.id} className="run-row"><span className="run-icon">{run.classification === "FALSE_REWARD" ? "!" : "·"}</span><span><strong>{run.candidate}</strong><small>{new Date(run.created_at).toLocaleString()}</small></span><span className={`status status-${run.state.toLowerCase()}`}>{run.classification ?? run.state}</span><span className="row-arrow">↗</span></Link>)}</div>
          )}
        </section>
        <section className="panel start-panel">
          <span className="section-kicker">NEW EXPERIMENT</span><h2>Run a control</h2>
          <p>Choose a fixture candidate. The API records your request, then a separate worker evaluates it in Docker and stores the evidence.</p>
          <NewRunForm />
          <div className="start-note">This interface does not accept arbitrary uploaded code.</div>
        </section>
      </div>
    </div>
  );
}
