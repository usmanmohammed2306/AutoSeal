import Link from "next/link";
import { fetchApi, type Run } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Runs() {
  let runs: Run[] = [];
  let error = false;
  try { runs = await fetchApi<Run[]>("/api/runs?limit=100"); } catch { error = true; }
  return <div className="page"><div className="eyebrow">EVIDENCE ARCHIVE</div><h1 className="page-title">Runs and evidence</h1><p className="lead compact">Every result here comes from a persisted request and a worker-produced evidence record.</p>{error && <div className="notice">The API is not reachable.</div>}<section className="panel wide"><div className="panel-header"><h2>All runs</h2><span className="count-pill">{runs.length} records</span></div>{runs.length === 0 ? <p className="empty">No recorded runs yet.</p> : <div className="run-list">{runs.map((run) => <Link href={`/runs/${run.id}`} key={run.id} className="run-row"><span className="run-icon">{run.classification === "FALSE_REWARD" ? "!" : "·"}</span><span><strong>{run.candidate}</strong><small>{run.id}</small></span><span className={`status status-${run.state.toLowerCase()}`}>{run.classification ?? run.state}</span><span className="row-arrow">↗</span></Link>)}</div>}</section></div>;
}
