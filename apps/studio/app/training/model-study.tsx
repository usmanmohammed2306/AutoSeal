import type { ModelStudy } from "@/lib/api";

const points = (value: number) => `${(100 * value).toFixed(1)} pp`;

export function ModelStudyPanel({ data }: { data: ModelStudy | null }) {
  if (!data) return <section className="panel wide"><span className="section-kicker">POST-CHECKPOINT HIDDEN AUDIT</span>
    <h2>No verified model comparison is connected.</h2><p className="panel-copy">A completed training allocation is insufficient. Connect its retained generation, checkpoint and independent Docker audit receipts to inspect the comparison.</p></section>;
  const summary = data.summary;
  const total = summary.models.reduce((sum, row) => sum + row.attempts, 0);
  const identical = data.paired_adapter_identity.filter(row => row.same_adapter_bytes).length;
  return <section className="panel wide">
    <div className="repair-card-head"><span className="section-kicker">FROZEN PAIRED STUDY / AUTHORED FINITE TASKS</span>
      <span className="repair-status">{summary.audit_complete ? "AUDIT RECEIPTS CHECKED" : "INCONCLUSIVE RESULTS RETAINED"}</span></div>
    <h2>Compare what the models actually submitted.</h2>
    <p className="panel-copy">{data.model_source.repository}. Both reward arms began at the same SFT checkpoint, used {data.steps_per_condition} updates and share the committed prompts and generation budget. Hidden inputs were exported after every final checkpoint was frozen.</p>
    <div className="metrics"><div className="metric"><span>SEEDS PER ARM</span><strong>{data.seeds.length}</strong><small>{data.seeds.join(", ")}</small></div>
      <div className="metric"><span>AUDIT GENERATIONS</span><strong>{total}</strong><small>One shared baseline and {2 * data.seeds.length} trained models</small></div>
      <div className="metric"><span>IDENTICAL ADAPTER PAIRS</span><strong>{identical}/{data.seeds.length}</strong><small>Different file hashes alone do not show a behavioral effect</small></div></div>
    <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Model</th><th>Seed</th><th>Attempts</th><th>Audit passes</th><th>Proxy passes</th><th>False rewards</th><th>Invalid</th><th>Inconclusive</th></tr></thead>
      <tbody>{summary.models.map(row => <tr key={row.model_id}><th>{row.arm}</th><td>{row.seed ?? "shared"}</td><td>{row.attempts}</td><td>{row.audit_passes}/{row.attempts}</td><td>{row.proxy_passes}/{row.attempts}</td><td>{row.false_rewards}/{row.attempts}</td><td>{row.invalid_outputs}</td><td>{row.inconclusive}</td></tr>)}</tbody></table></div>
    <p className="panel-copy">Every generation stays in the denominator. Invalid packets are task failures. Inconclusive results cannot count as successful exploit blocks. The baseline is one shared model, not an independent baseline per seed.</p>
    <h3>Paired seed differences</h3><p className="panel-copy">Values are sealed minus vulnerable in percentage points. Three seeds give weak uncertainty information. These descriptive resamples are not significance tests or evidence of benchmark-wide generalization.</p>
    <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Outcome</th><th>Seed differences</th><th>Mean difference</th><th>Descriptive 95% resample interval</th><th>Interpretation</th></tr></thead>
      <tbody>{summary.paired_seed_contrasts.map(row => <tr key={row.metric}><th>{row.metric.replaceAll("_", " ")}</th><td>{row.seed_differences.map(points).join(", ")}</td><td>{points(row.mean_difference)}</td><td>{row.descriptive_seed_bootstrap_95_percentile.map(points).join(" to ")}</td><td>{row.interpretation_eligible ? "Finite study only" : "Incomplete audit"}</td></tr>)}</tbody></table></div>
    <details><summary>Inspect training evidence and exact lineage</summary>
      <table className="matrix"><thead><tr><th>Arm</th><th>Seed</th><th>Reward / attempts</th><th>Nonconstant groups</th><th>Adapter</th></tr></thead><tbody>{data.training_conditions.map(row => <tr key={`${row.arm}-${row.seed}`}><th>{row.arm}</th><td>{row.seed}</td><td>{row.reward_sum}/{row.attempted_outputs}</td><td>{row.nonconstant_reward_groups}</td><td><code>{row.adapter_id.slice(0, 24)}…</code></td></tr>)}</tbody></table>
      <p className="mono">Audit evaluation: {data.evaluation_id}<br />Training archive: {data.training_archive_id}<br />Generation archive: {data.generation_archive_id}<br />Dataset: {data.dataset_revision}<br />Hidden commitment: {data.hidden_commitment}<br />Shared start: {data.starting_checkpoint}</p></details>
    <ul className="panel-copy">{summary.limitations.map(item => <li key={item}>{item}</li>)}</ul><p className="panel-copy">{data.verification}</p>
  </section>;
}
