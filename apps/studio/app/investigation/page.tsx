import { fetchApi, type InfluenceResponse } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Investigation() {
  let data: InfluenceResponse | null = null;
  try { data = await fetchApi<InfluenceResponse>("/api/research/fixtures/exploit/influence"); }
  catch { /* Surface an explicit unavailable state. */ }
  const edge = data?.graph.edges.find((item) => item.relation === "AFFECTS_REWARD");
  return <div className="page">
    <div className="eyebrow">CAUSAL INVESTIGATION / CHECKED-IN FIXTURE</div>
    <h1 className="page-title">Follow the false reward.</h1>
    <p className="lead compact">A controlled intervention asks whether one candidate-owned file changes the proxy verdict while the solution stays fixed. This view shows only the claim the experiment supports.</p>
    {!data ? <div className="notice error">The local research API is unavailable. Start the API to inspect this experiment.</div> : <>
      <section className="panel wide"><div className="panel-header"><div><span className="section-kicker">INFLUENCE PATH</span><h2>One file crosses the scoring boundary</h2></div><span className="count-pill">{data.graph.resolution.toUpperCase()}</span></div>
        <div className="causal-flow"><div className="causal-node candidate"><small>CANDIDATE CONTROLLED</small><strong>{edge?.source.replace("candidate:", "") ?? "Unknown"}</strong><span>present in proxy workspace</span></div><div className="causal-arrow"><span>INTERVENTION</span>→</div><div className="causal-node reward"><small>TRUSTED REWARD</small><strong>Proxy PASS</strong><span>audit verdict: REJECT</span></div></div>
        {edge && <><p className="causal-explanation">{edge.explanation}</p><div className="evidence-pair">{edge.evidence_ids.map((id, index) => <div key={id}><span>{index === 0 ? "File present" : "File removed"}</span><code>{id}</code></div>)}</div></>}
        <div className="notice">Mechanism status: {data.graph.mechanism_status.replace("_", " ").toLowerCase()}. The intervention proves file-level influence, not the exact internal Pytest call path.</div>
      </section>
      <div className="detail-grid"><section className="panel"><span className="section-kicker">MINIMAL WITNESS</span><h2>What remains necessary?</h2><div className="witness-result"><strong>{data.witness.essential_files.join(", ") || "No extra file"}</strong><span>essential candidate-owned file</span></div><p className="panel-copy">The search made {data.witness.query_count} controlled queries. Minimal within the tested file granularity: {data.witness.minimal_within_file_granularity ? "yes" : "not established"}.</p></section><section className="panel"><span className="section-kicker">INTERVENTION LEDGER</span><h2>Keep, remove, observe</h2><div className="ledger">{data.witness.interventions.map((item, index) => <div className="ledger-row" key={`${item.process_evidence_id}-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><strong>{item.kept_files.join(" + ")}</strong><em className={item.proxy_verdict === "PASS" ? "pass" : "reject"}>{item.proxy_verdict}</em></div>)}</div></section></div>
    </>}
  </div>;
}
