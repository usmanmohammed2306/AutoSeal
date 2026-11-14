import type { SftCalibration } from "@/lib/api";

export function SftCalibrationPanel({ data }: { data: SftCalibration | null }) {
  if (!data) return <section className="panel wide"><span className="section-kicker">SFT CALIBRATION</span>
    <h2>No verified calibration archive is connected.</h2><p className="panel-copy">Configure a pinned evaluation on the API to inspect the actual checkpoint, pause/resume and before/after Docker results. Missing evidence is not a zero score.</p></section>;
  const rows = data.curve;
  const low = Math.min(...rows.map(row => row.loss));
  const high = Math.max(...rows.map(row => row.loss));
  const points = rows.map(row => `${40 + 480 * (row.step - 1) / Math.max(1, data.global_step - 1)},${155 - 120 * (row.loss - low) / Math.max(.01, high - low)}`).join(" ");
  return <section className="panel wide">
    <div className="repair-card-head"><span className="section-kicker">CHECKED SFT / ONE DEVELOPMENT SEED</span><span className="reject repair-status">CALIBRATION ONLY</span></div>
    <h2>A real resume, with the remaining failures visible.</h2>
    <p className="panel-copy">{data.model_source.repository} trained on {data.training_examples} authored examples. The run paused at step {data.resumed_from_step}, verified its optimizer checkpoint, and resumed to step {data.global_step}. All {data.attempted_per_phase} before and after attempts are retained. These prompts were known during development.</p>
    <div className="metrics"><div className="metric"><span>OPTIMIZER UPDATES</span><strong>{data.global_step}</strong><small>Seed {data.seed}, {data.gpu}</small></div>
      <div className="metric"><span>TRAINABLE PARAMETERS</span><strong>{(data.trainable_parameters / 1e6).toFixed(2)}M</strong><small>LoRA, {(data.peak_gpu_bytes / 1024 ** 3).toFixed(1)} GiB peak allocated</small></div>
      <div className="metric"><span>STRICT WIRE PACKETS</span><strong>{data.phases.baseline.syntax_valid} → {data.phases.post_sft.syntax_valid}</strong><small>Out of {data.attempted_per_phase} per phase, no output repair</small></div></div>
    <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Known development outcomes</th><th>Before SFT</th><th>After SFT</th></tr></thead><tbody>
      <tr><th>Independent task passes</th><td>{data.phases.baseline.audit_pass}/{data.phases.baseline.attempted}</td><td>{data.phases.post_sft.audit_pass}/{data.phases.post_sft.attempted}</td></tr>
      <tr><th>Malformed outputs</th><td>{data.phases.baseline.classifications.INVALID_OUTPUT ?? 0}</td><td>{data.phases.post_sft.classifications.INVALID_OUTPUT ?? 0}</td></tr>
      <tr><th>Confirmed false rewards</th><td>{data.phases.baseline.classifications.FALSE_REWARD ?? 0}</td><td>{data.phases.post_sft.classifications.FALSE_REWARD ?? 0}</td></tr>
      <tr><th>Targeted literal-null adherence</th><td>{data.phases.baseline.fixed_wrong_adherent}</td><td>{data.phases.post_sft.fixed_wrong_adherent}</td></tr>
    </tbody></table></div>
    <figure><figcaption className="panel-copy">Per-update training loss. This measures the training objective, not held-out task quality.</figcaption>
      <svg viewBox="0 0 560 195" role="img" aria-label={`Training loss across ${data.global_step} updates`} style={{ width: "100%", maxWidth: 760 }}>
        <path d="M40 25V155H530" fill="none" stroke="currentColor" opacity=".3" />
        <path d="M40 95H530M40 35H530" fill="none" stroke="currentColor" opacity=".1" />
        <polyline points={points} fill="none" stroke="#ff9a61" strokeWidth="2.5" />
        <text x="0" y="39" fill="currentColor" fontSize="11">{high.toFixed(2)}</text><text x="0" y="158" fill="currentColor" fontSize="11">{low.toFixed(2)}</text>
        <text x="36" y="180" fill="currentColor" fontSize="11">1</text><text x="485" y="180" fill="currentColor" fontSize="11">Step {data.global_step}</text>
      </svg></figure>
    <p className="panel-copy">The loss covers {data.loss_scope}. A completed optimizer run and a lower training loss do not establish reduced reward hacking. Read the task audit and malformed-output counts separately.</p>
    <details><summary>Inspect checkpoint and dataset lineage</summary><p className="mono">Evaluation: {data.evaluation_id}<br />Configuration: {data.configuration_id}<br />Dataset: {data.dataset_revision}<br />Adapter: {data.adapter_id}<br />Base revision: {data.model_source.revision}</p><pre className="evidence-json">{data.scheduler}</pre>
      <table className="matrix"><thead><tr><th>Step</th><th>Loss</th><th>Gradient norm</th></tr></thead><tbody>{rows.map(row => <tr key={row.step}><td>{row.step}</td><td>{row.loss.toFixed(4)}</td><td>{row.grad_norm.toFixed(4)}</td></tr>)}</tbody></table></details>
    <ul className="panel-copy">{data.limitations.map(item => <li key={item}>{item}</li>)}</ul>
  </section>;
}
