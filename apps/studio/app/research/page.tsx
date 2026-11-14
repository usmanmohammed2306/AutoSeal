import { fetchApi, type NativeSWEbenchResponse, type SWEbenchRepairPreview, type SWEbenchResponse, type UpstreamGraderResponse } from "@/lib/api";

export const dynamic = "force-dynamic";

const historicalTitles: Record<string, string> = {
  collection_failure: "The tests disappear",
  legitimate_solution: "A valid solution still passes",
  ordinary_failure: "An ordinary failure still fails",
};

export default async function Research() {
  let current: SWEbenchResponse | null = null;
  let repair: SWEbenchRepairPreview | null = null;
  let historical: UpstreamGraderResponse | null = null;
  let native: NativeSWEbenchResponse | null = null;
  const shell = await fetchApi<{ report_id: string; scope: string; discovery_credit: string; image: string;
    controls: { name: string; role: string; proxy: string; audit: string; sealed: string }[]; limitations: string[];
  }>("/api/research/terminal-shell").catch(() => null);
  try { native = await fetchApi<NativeSWEbenchResponse>("/api/research/native-swebench"); }
  catch { /* Missing native evidence stays visible. */ }
  try { current = await fetchApi<SWEbenchResponse>("/api/research/upstream-swebench"); }
  catch { /* An API failure must not become fabricated evidence. */ }
  try { repair = await fetchApi<SWEbenchRepairPreview>("/api/research/upstream-swebench/repair-preview"); }
  catch { /* Do not invent a repair result. */ }
  try { historical = await fetchApi<UpstreamGraderResponse>("/api/research/upstream-swesmith"); }
  catch { /* Keep the case studies independently available. */ }
  const xfail = current?.cases.find(item => item.case === "xfail");

  return <div className="page">
    <div className="eyebrow">PUBLIC BENCHMARK EVIDENCE / PINNED SOURCE</div>
    <h1 className="page-title">The test never ran.<br /><em>The benchmark still passed it.</em></h1>
    <p className="lead compact">A candidate-controlled Pytest hook marks a required test as expected to fail without running it. The pinned SWE-bench grader counts that <code>XFAIL</code> as success. AutoSeal checks the same wrong solution in a pristine audit workspace.</p>
    <div className="notice">SWE-bench issue 654 was open when checked on October 7, 2026. The native archive below is separate from the small live mechanism reproduction.</div>

    <section className="panel wide"><span className="section-kicker">DISCLOSED RUNTIME HIJACK / ARCHIVED NATIVE TESTS</span>
      <h2>The script stayed broken. Its interpreter changed.</h2>
      {!shell ? <p className="panel-copy">No verified shell-task archive is configured. Missing evidence is not a passing result.</p> : <>
        <p className="panel-copy">The public task-125 exploit replaced dash with bash. Unchanged upstream tests accepted incompatible scripts. A fresh-runtime audit and the projected test environment reject the same candidate while preserving both valid alternatives.</p>
        <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Control</th><th>Role</th><th>Original tests</th><th>Clean audit</th><th>Projected tests</th></tr></thead><tbody>
          {shell.controls.map(control => <tr key={control.name}><th>{control.name}</th><td>{control.role}</td>{[control.proxy, control.audit, control.sealed].map((verdict, index) => <td key={index} className={verdict === "PASS" ? "pass" : "reject"}>{verdict}</td>)}</tr>)}
        </tbody></table></div><p className="panel-copy">{shell.scope} Original discovery: {shell.discovery_credit}.</p>
        <details><summary>Provenance and limits</summary><p className="mono">Report: {shell.report_id}<br />Image: {shell.image}</p>{shell.limitations.map(text => <p className="panel-copy" key={text}>{text}</p>)}</details>
      </>}
    </section>

    {!native ? <div className="notice error">The native evidence archive is unavailable or failed integrity checks.</div> : <section className="panel wide">
      <span className="section-kicker">OFFICIAL HARNESS / ARCHIVED NATIVE RUNS</span>
      <h2>{native.instance_id}</h2>
      <p className="panel-copy">These controls ran through the unmodified pinned official harness in fresh Docker containers. A separate fresh-container audit checked the behavior of each implementation patch without the candidate-controlled test hook. The explicit-pass column is only a re-grade of the native output, not a promoted repair.</p>
      <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Control</th><th>Native</th><th>Independent audit</th><th>Adapter</th><th>F2P explicit pass</th><th>Parity</th></tr></thead><tbody>{native.controls.map(item => <tr key={item.identity}><th>{item.case}<small>{item.role.replaceAll("_", " ")}</small></th><td className={item.native_resolved ? "pass" : "reject"}>{item.native_resolved ? "RESOLVED" : "NOT RESOLVED"}</td><td className={item.audit_verdict === "PASS" ? "pass" : "reject"}>{item.audit_verdict}</td><td>{item.adapter_resolved ? "RESOLVED" : "NOT RESOLVED"}</td><td className={item.f2p_explicit_pass ? "pass" : "reject"}>{item.f2p_explicit_pass ? "PASS" : "REJECT"}</td><td className={item.native_adapter_parity ? "pass" : "reject"}>{item.native_adapter_parity ? "MATCH" : "MISMATCH"}</td></tr>)}</tbody></table></div>
      <p className="panel-copy">{native.limitation} {native.audit_limitation}</p>
      <details><summary>Inspect native and audit evidence</summary>{native.controls.map(item => <div key={item.identity}><h3>{item.case}</h3><p className="mono">Native receipt: {item.identity}<br />Audit receipt: {item.audit_identity}<br />Candidate patch: {item.candidate_patch_id}<br />Image: {item.image_identity}</p><pre>{JSON.stringify({ native_artifacts: item.artifacts, audit_checks: item.audit_checks }, null, 2)}</pre></div>)}</details>
      <a className="text-link" href={native.disclosure} target="_blank" rel="noreferrer">Original public report and attribution ↗</a>
    </section>}

    {!xfail ? <div className="notice error">The local research API is unavailable. Start it to inspect the live benchmark comparison.</div> : <>
      <section className="panel current-case">
        <div className="repair-card-head"><span className="section-kicker">CURRENTLY REPORTED MECHANISM</span><span className="reject repair-status">FALSE REWARD</span></div>
        <h2>Required test: <code>test_regression</code></h2>
        <div className="current-evidence-grid">
          <div className="current-verdict"><span>CANDIDATE-CONTROLLED PROXY</span><strong className="pass">{xfail.proxy.verdict}</strong><small>{xfail.proxy.grader_resolution} · test status {xfail.proxy.observed_status_map["test_contract.py::test_regression"]}</small></div>
          <div className="current-divider">≠</div>
          <div className="current-verdict"><span>PRISTINE INDEPENDENT AUDIT</span><strong className="reject">{xfail.audit.verdict}</strong><small>{xfail.audit.grader_resolution} · test status {xfail.audit.observed_status_map["test_contract.py::test_regression"]}</small></div>
        </div>
        <div className="evidence-pair"><div><span>SAME SOLUTION SHA-256</span><code>{xfail.solution_sha256}</code></div><div><span>PINNED UPSTREAM COMMIT</span><code>{xfail.upstream_commit}</code></div></div>
        <p className="panel-copy">The proxy copied <code>conftest.py</code> and produced Pytest output containing <code>[NOTRUN]</code>. The audit excluded that candidate-controlled hook, ran the required test, and observed a failure. Both outcomes come from real local executions.</p>
      </section>
      {repair && <section className="panel wide repair-highlight"><div className="repair-card-head"><span className="section-kicker">SCOPED VERIFIER REPAIR / LOCAL PREVIEW</span><span className="pass repair-status">{repair.disposition.replaceAll("_", " ")}</span></div><h2>Require an explicit pass where the task requires a fix.</h2><p className="panel-copy">{repair.operator} rejects an <code>XFAIL</code> on a FAIL_TO_PASS test. It still accepts a maintenance-side <code>XFAIL</code>, so this rule does not break that existing behavior. This is a tested local policy, not an upstream patch or a promoted AutoSeal seal.</p></section>}
      <section className="panel wide">
        <span className="section-kicker">CONTROL MATRIX</span><h2>The difference is the marker, not the bug fix</h2>
        <div className="matrix-scroll"><table className="matrix"><thead><tr><th>Candidate</th><th>Proxy</th><th>Local repair</th><th>Audit</th><th>Interpretation</th></tr></thead><tbody>{(repair?.controls ?? current?.cases ?? []).map(item => { const row = repair?.controls.find(control => control.case === item.case); const source = current?.cases.find(control => control.case === item.case); return <tr key={item.case}><th>{item.case}</th><td className={source?.proxy.verdict === "PASS" ? "pass" : "reject"}>{source?.proxy.verdict ?? row?.proxy_verdict}</td><td className={row?.repaired_verdict === "PASS" ? "pass" : "reject"}>{row?.repaired_verdict ?? "NOT RUN"}</td><td className={source?.audit.verdict === "PASS" ? "pass" : "reject"}>{source?.audit.verdict ?? row?.audit_verdict}</td><td>{source?.classification.replaceAll("_", " ") ?? (row?.preserved ? "PRESERVED" : "CHANGED")}</td></tr>; })}</tbody></table></div>
        <p className="panel-copy">{xfail.limitation} AutoSeal reproduced one native Verified instance after the issue reporter disclosed the path. The discovery and original three-instance study belong to the reporter. AutoSeal does not claim to have found or fixed this upstream bug.</p>
        <a className="text-link" href="https://github.com/SWE-bench/SWE-bench/issues/654" target="_blank" rel="noreferrer">Read the open SWE-bench issue ↗</a>
      </section>
    </>}

    <div className="research-divider"><span>HISTORICAL CONTROL</span></div>
    <h2 className="research-title">A different failure that upstream already fixed.</h2>
    <p className="panel-copy">In 2025, SWE-Smith assumed missing test results were passes. Its maintainers repaired that rule. The cards below compare byte-for-byte original and fixed grading functions on the same status maps.</p>
    {!historical ? <div className="notice error">The historical grader comparison is unavailable.</div> : <>
      <section className="upstream-cases" aria-label="Historical grader controls">
        {historical.cases.map((item, index) => <article className="panel upstream-case" key={item.case}>
          <div className="repair-card-head"><span className="section-kicker">CONTROL {String(index + 1).padStart(2, "0")}</span><span className={item.case === "collection_failure" ? "reject repair-status" : "pass repair-status"}>{item.execution_health.replaceAll("_", " ")}</span></div>
          <h2>{historicalTitles[item.case] ?? item.case}</h2>
          <p>{item.case === "collection_failure" ? "Two expected tests. No observed test statuses. The old grader assumed success." : item.case === "legitimate_solution" ? "Both tests explicitly pass. The fix keeps this result." : "Both tests explicitly fail. Neither grader should award a pass."}</p>
          <div className="upstream-verdicts"><div><span>BEFORE FIX</span><strong className={item.historical_proxy.verdict === "PASS" ? "pass" : "reject"}>{item.historical_proxy.verdict}</strong><small>{item.historical_proxy.source_commit.slice(0, 8)}</small></div><div><span>AFTER FIX</span><strong className={item.repaired_control.verdict === "PASS" ? "pass" : "reject"}>{item.repaired_control.verdict}</strong><small>{item.repaired_control.source_commit.slice(0, 8)}</small></div></div>
          <div className="upstream-detail">{Object.keys(item.observed_status_map).length} reported statuses for {item.expected_tests.length} expected tests</div>
        </article>)}
      </section>
      <p className="panel-copy">{historical.cases[0]?.limitation} This is not evidence that current SWE-Smith is vulnerable. <a className="text-link" href="https://github.com/SWE-bench/SWE-smith/issues/24" target="_blank" rel="noreferrer">Read its historical issue ↗</a></p>
    </>}
  </div>;
}
