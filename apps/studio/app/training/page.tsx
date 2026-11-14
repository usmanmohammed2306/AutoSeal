import { Suspense } from "react";
import { fetchApi, type ModelStudy, type SftCalibration, type TrainingPilotsResponse } from "@/lib/api";
import { SftCalibrationPanel } from "./sft-calibration";
import { ModelStudyPanel } from "./model-study";

export const dynamic = "force-dynamic";

function formatReward(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(3);
}

async function LegacyTrainingEvidence() {
  let data: TrainingPilotsResponse | null = null;
  try { data = await fetchApi<TrainingPilotsResponse>("/api/research/training-pilots"); }
  catch { /* Missing historical evidence stays unavailable. */ }
  return <>
    {data?.preflights?.length ? <section className="panel wide">
      <div className="repair-card-head"><span className="section-kicker">LATEST ONE-ARM PREFLIGHTS</span><span className="reject repair-status">NOT A PAIRED STUDY</span></div>
      <h2>From a failed boundary to one real gradient.</h2>
      <p className="panel-copy">These are separate one-seed experiments, not a paired efficacy study. The outcome of each attempt stays visible.</p>
      <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Attempt</th><th>Job result</th><th>Steps</th><th>Model outputs</th><th>Reward / outputs</th><th>Peak gradient</th><th>Evidence</th></tr></thead><tbody>{data.preflights.map(item => <tr key={item.id}>
        <th>{item.id.toUpperCase().replaceAll("_", " ")}</th><td>{item.report_status}</td><td>{item.global_steps}</td>
        <td>{Object.entries(item.outcomes).map(([kind, count]) => `${kind}: ${count}`).join(", ")}</td>
        <td>{formatReward(item.reward_sum)}/{item.samples}</td>
        <td>{item.max_gradient_norm.toFixed(4)}</td><td><code>{item.report_id.slice(0, 22)}…</code></td>
      </tr>)}</tbody></table></div>
      <p className="panel-copy">G exposed a candidate-error classification bug. H completed with zero rewards and zero gradient. I used a separately frozen diagnostic pass-fraction reward, got one 1/7 sample and one nonzero gradient step. The matching sealed arm appears below and produced the same adapter. There is no held-out audit or downstream improvement claim. The checked evidence is in the local training archive until you publish it.</p>
    </section> : null}
    {!data ? <div className="notice error">The training evidence API is unavailable or its archive failed integrity checks.</div> : !data.pilots.length ? <div className="notice">No verified training pilot archive has been published yet.</div> : data.pilots.map(pilot => {
      const rows = pilot.summary.conditions;
      const seeds = new Set(rows.map(row => row.seed)).size;
      const samples = rows.reduce((total, row) => total + row.samples, 0);
      const invalid = rows.reduce((total, row) => total + (row.outcomes.INVALID_OUTPUT ?? 0), 0);
      const rewards = rows.reduce((total, row) => total + row.reward_sum, 0);
      return <section className="panel wide" key={pilot.id}>
        <div className="repair-card-head"><span className="section-kicker">{pilot.id.toUpperCase().replaceAll("_", " ")}</span><span className="reject repair-status">SMOKE ONLY</span></div>
        <h2>{pilot.summary.nonzero_within_batch_reward_variance ? "The reward varied within at least one batch." : "No within-batch reward contrast was observed."}</h2>
        <div className="metrics">
          <div className="metric"><span>PAIRED CONDITIONS</span><strong>{rows.length}</strong><small>{seeds} seed{seeds === 1 ? "" : "s"} per arm</small></div>
          <div className="metric"><span>REWARD TOTAL</span><strong>{formatReward(rewards)}</strong><small>{samples} samples; {invalid} invalid outputs</small></div>
          <div className="metric"><span>RESEARCH CLAIM</span><strong>{pilot.summary.downstream_improvement_established ? "YES" : "NO"}</strong><small>Hidden audit not run</small></div>
        </div>
        <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Seed</th><th>Reward arm</th><th>Steps</th><th>Outcomes</th><th>Reward / outputs</th><th>Adapter identity</th></tr></thead><tbody>{rows.map(row => <tr key={`${row.arm}-${row.seed}`}><th>{row.seed}</th><td>{row.arm}</td><td>{row.global_steps}</td><td>{Object.entries(row.outcomes).map(([kind, count]) => `${kind}: ${count}`).join(", ")}</td><td>{formatReward(row.reward_sum)}/{row.samples}</td><td><code>{row.adapter_identity.slice(0, 22)}…</code></td></tr>)}</tbody></table></div>
        <p className="panel-copy">{pilot.summary.limitation} {pilot.missing_frozen_source_files === undefined ? "Source archive completeness was not recorded for this early pilot." : pilot.missing_frozen_source_files.length ? `Frozen source bytes missing from this archive: ${pilot.missing_frozen_source_files.join(", ")}.` : "Frozen source bytes are archived."}</p>
        <details><summary>Inspect exact lineage</summary><p className="mono">Configuration: {pilot.configuration_id}<br />Model snapshot: {pilot.summary.model_snapshot_revision}<br />Archived content objects: {pilot.objects}</p></details>
      </section>;
    })}
  </>;
}

async function VerifiedStudy() {
  let data: ModelStudy | null = null;
  try { data = await fetchApi<ModelStudy>("/api/research/model-study"); }
  catch { /* A failed check never becomes a demonstration result. */ }
  return <ModelStudyPanel data={data} />;
}

async function VerifiedCalibration() {
  let data: SftCalibration | null = null;
  try { data = await fetchApi<SftCalibration>("/api/research/sft-calibration"); }
  catch { /* Keep unavailable calibration evidence explicit. */ }
  return <SftCalibrationPanel data={data} />;
}

function CheckingEvidence({ title }: { title: string }) {
  return <section className="panel wide" role="status"><span className="section-kicker">VERIFYING SAVED EVIDENCE</span>
    <h2>{title}</h2><p className="panel-copy">Reading the retained receipts and their lineage. This page starts no model, training or candidate execution.</p></section>;
}

export default function TrainingEvidence() {
  return <div className="page">
    <div className="eyebrow">OPEN-WEIGHT MODEL / ACTUAL A100 TRAINING</div>
    <h1 className="page-title">Follow the model<br /><em>through the audit.</em></h1>
    <p className="lead compact">Inspect paired model audits, SFT calibration and earlier GRPO bridge pilots. Trusted model work runs on Sol A100s; candidate evaluation runs in Mac Docker. Each panel checks its saved evidence independently.</p>
    <Suspense fallback={<CheckingEvidence title="Checking the saved model comparison." />}><VerifiedStudy /></Suspense>
    <Suspense fallback={<CheckingEvidence title="Checking the SFT checkpoint." />}><VerifiedCalibration /></Suspense>
    <Suspense fallback={<CheckingEvidence title="Loading earlier experiments." />}><LegacyTrainingEvidence /></Suspense>
    <div className="notice">Full V1 still requires its complete external-case, preservation, enforcement, baseline, ablation and operated-delivery evidence. A model comparison on authored finite tasks has a narrower scope. Null and adverse findings remain visible.</div>
  </div>;
}
