import { fetchApi, type ManagedRepairResponse, type PromotionReviewResponse, type RepairPlanPreviewResponse, type RepairPreviewResponse } from "@/lib/api";

export const dynamic = "force-dynamic";

const previewGates = [
  ["exploit_blocked", "Exploit blocked"],
  ["positives_preserved", "Legitimate solutions preserved"],
  ["negatives_preserved", "Invalid solutions rejected"],
  ["heldout_blocked", "Development variant blocked"],
  ["repeatable", "Repeatable verdict"],
] as const;

const gateLabels: Record<string, string> = {
  frozen_corpus_identity: "Frozen corpus identity",
  complete_process_evidence: "Complete process evidence",
  baseline_oracle: "Native and audit baseline",
  exploit_exclusion: "Exploit exclusion",
  positive_preservation: "Positive preservation",
  negative_preservation: "Negative preservation",
  unaffected_native_parity: "Unaffected native parity",
  heldout_reattack: "Held-out re-attack",
  repeatable_verdicts: "Repeatable verdicts",
  early_termination_resistance: "Early termination resistance",
  provider_enforcement: "Provider enforcement",
  privilege_and_rollback: "Privilege and rollback",
};

export default async function Repairs() {
  const [preview, promotion, composed, managed] = await Promise.all([
    fetchApi<RepairPreviewResponse>("/api/research/repair-preview").catch(() => null),
    fetchApi<PromotionReviewResponse>("/api/research/promotion-review").catch(() => null),
    fetchApi<RepairPlanPreviewResponse>("/api/research/repair-plan-preview").catch(() => null),
    fetchApi<ManagedRepairResponse>("/api/research/managed-repair").catch(() => null),
  ]);

  return <div className="page">
    <div className="eyebrow">TYPED REPAIR SEARCH / PROMOTION FIREWALL</div>
    <h1 className="page-title">Block the exploit.<br /><em>Keep the contract.</em></h1>
    <p className="lead compact">A repair is not good just because the exploit stops. Valid solutions, ordinary negatives, a separately frozen re-attack, native parity, and the execution boundary all matter.</p>

    <section className="panel wide"><span className="section-kicker">RETAINED DOCKER VALIDATION</span>
      {!managed ? <><h2>No verified runtime archive available</h2><p>Configure a pinned managed-validation report on the local API. Missing or corrupt evidence cannot become a passing repair.</p></> : <>
        <div className="repair-card-head"><h2>Measured behavior, verified rollback</h2><span className="repair-status reject">{managed.disposition}</span></div>
        <p>Saved execution from {new Date(managed.run_metadata.started_at_utc).toISOString()}. {managed.run_metadata.evaluations} candidate evaluations{managed.run_metadata.capability_probe_executions ? ` and ${managed.run_metadata.capability_probe_executions} capability probe` : ""} in {managed.run_metadata.elapsed_seconds.toFixed(2)} seconds. This is the {managed.scope}. No repair was promoted.</p>
        <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Control</th><th>Proxy</th><th>Audit</th><th>Sealed repeats</th></tr></thead><tbody>{managed.controls.map(control => <tr key={control.name}><th>{control.name}<small>{control.role}</small></th><td>{control.proxy}</td><td>{control.audit}</td><td>{control.sealed.join(" / ")}</td></tr>)}</tbody></table></div>
        <div className="gate-list">{Object.entries(managed.gates).map(([name, passed]) => <div className="gate-row" key={name}><span>{name.replaceAll("_", " ")}</span><strong className={passed ? "pass" : "reject"}>{passed ? "PASS" : "MISSING"}</strong></div>)}</div>
        <p>The early-exit control remains {managed.stress.verdict}, with {managed.stress.counts.failed} functional failures. It is excluded from successful block counts.</p>
        <p>{managed.verification}</p><p className="mono">Report: {managed.report_id}<br />Rollback: {managed.rollback_id}</p>
        {managed.enforcement_probe && <details><summary>Owned-verifier capability probe: {managed.enforcement_probe.passed ? "passed" : "failed"}</summary><div className="gate-list">{Object.entries(managed.enforcement_probe.gates).map(([name, passed]) => <div className="gate-row" key={name}><span>{name.replaceAll("_", " ")}</span><strong className={passed ? "pass" : "reject"}>{passed ? "PASS" : "FAIL"}</strong></div>)}</div><p className="mono">Probe: {managed.enforcement_probe.identity}</p><ul>{managed.enforcement_probe.limitations.map(item => <li key={item}>{item}</li>)}</ul></details>}
        <ul>{managed.limitations.map(item => <li key={item}>{item}</li>)}</ul>
      </>}
    </section>

    {!preview ? <div className="notice error">The local research API is unavailable. Start the API to inspect repair candidates.</div> : <>
      <div className="notice">{preview.scope}. Local eligibility is not a promotion decision.</div>
      <div className="repair-grid">{preview.plans.map((item, index) => <section className="panel repair-card" key={`${item.plan.operator}-${index}`}>
        <div className="repair-card-head"><span className="section-kicker">PLAN {String(index + 1).padStart(2, "0")}</span><span className={`repair-status ${item.status === "ELIGIBLE_LOCAL" ? "pass" : "reject"}`}>{item.status === "ELIGIBLE_LOCAL" ? "LOCAL ELIGIBLE" : "REJECTED"}</span></div>
        <h2>{item.plan.operator}</h2>
        <p>{item.plan.allowed_files.length ? `Project only ${item.plan.allowed_files.join(", ")}` : item.plan.required_passes ? `Require ${item.plan.required_passes} passing tests` : "Bind the result to trusted identities"}</p>
        <div className="gate-list">{previewGates.map(([key, label]) => <div className="gate-row" key={key}><span>{label}</span><strong className={item[key] ? "pass" : "reject"}>{item[key] ? "PASS" : "FAIL"}</strong></div>)}</div>
      </section>)}</div>

      <section className="panel wide"><span className="section-kicker">DEVELOPMENT CONTROL MATRIX</span><h2>Every candidate, every plan</h2><div className="matrix-scroll"><table className="matrix"><thead><tr><th>Candidate</th>{preview.plans.map((item, index) => <th key={index}>{item.plan.operator}<small>{index + 1}</small></th>)}</tr></thead><tbody>{preview.plans[0]?.outcomes.map((row, rowIndex) => <tr key={row.candidate}><th>{row.candidate}<small>Expected {row.expected}</small></th>{preview.plans.map((item, index) => <td key={index} className={item.outcomes[rowIndex]?.passed ? "pass" : "reject"}>{item.outcomes[rowIndex]?.observed ?? "MISSING"}</td>)}</tr>)}</tbody></table></div></section>
    </>}

    {composed && <section className="panel wide"><span className="section-kicker">COMPOSED REPAIR PLAN / DESIGN-TIME ONLY</span><h2>Three operators, one reversible policy chain</h2>
      <p>{composed.scope}. The plan removes an unapproved candidate file, transfers verdict ownership in policy, and binds the result to six identities. None of those declarations proves that a real provider enforces them.</p>
      <div className="repair-plan-chain">{composed.forward_operators.map((operator, index) => <div className="repair-plan-step" key={operator}><span className="section-kicker">STEP {String(index + 1).padStart(2, "0")}</span><strong>{operator}</strong></div>)}</div>
      <div className="gate-list"><div className="gate-row"><span>Exact policy inverse</span><strong className={composed.policy_rollback_exact ? "pass" : "reject"}>{composed.policy_rollback_exact ? "PASS" : "FAIL"}</strong></div><div className="gate-row"><span>Runtime provider enforcement</span><strong className="reject">UNPROVEN</strong></div><div className="gate-row"><span>Managed artifact rollback</span><strong className="reject">UNPROVEN</strong></div></div>
      <p className="mono">Plan: {composed.plan_identity}<br />Parent: {composed.parent_policy_identity}<br />Child: {composed.child_policy_identity}</p>
    </section>}

    {!promotion ? <div className="notice error">The promotion review is unavailable.</div> : <>
      <section className="panel wide"><span className="section-kicker">PROMOTION REVIEW / ARTIFACT PROJECTION</span><div className="repair-card-head"><h2>A blocked reward is not yet a validated repair</h2><span className="repair-status reject">{promotion.disposition}</span></div>
        <p>The projection rejects the original skip attack and preserves the tested valid solutions. A separate early-termination stress case still ends with no completed tests, so the repaired verdict is inconclusive, not a confirmed rejection. Provider enforcement and rollback are also unproven. No SealEvidence has been issued.</p>
        <div className="gate-list">{promotion.gates.map(gate => <div className="gate-row" key={gate.name} title={gate.detail}><span>{gateLabels[gate.name] ?? gate.name}</span><strong className={gate.passed ? "pass" : "reject"}>{gate.passed ? "PASS" : "MISSING"}</strong></div>)}</div>
        <p className="mono">Plan: {promotion.plan_identity}<br />Corpus: {promotion.corpus_identity}</p>
      </section>
      <section className="panel wide"><span className="section-kicker">FROZEN LOCAL CORPUS</span><h2>The search-excluded attack runs after plan selection</h2><div className="matrix-scroll"><table className="matrix"><thead><tr><th>Candidate</th><th>Native</th><th>Audit</th><th>Repaired</th></tr></thead><tbody>{promotion.controls.map(control => <tr key={control.name}><th>{control.name}<small>{control.role}</small></th><td>{control.native_verdict}</td><td>{control.audit_verdict}</td><td className={control.repaired_verdict === control.audit_verdict ? "pass" : "reject"}>{control.repaired_verdict}</td></tr>)}</tbody></table></div></section>
      <section className="panel wide"><span className="section-kicker">TERMINATION STRESS / FROZEN CONTROL</span><h2>The candidate ends the test runner early</h2><p>The proxy grants a pass with {promotion.termination_stress.proxy_completed_tests} completed tests. The repaired path reports {promotion.termination_stress.repaired_verdict} with {promotion.termination_stress.repaired_completed_tests} completed tests. That prevents a false reward, but it does not meet the semantic rejection gate.</p></section>
    </>}
  </div>;
}
