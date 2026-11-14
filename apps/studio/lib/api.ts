export type Run = {
  id: string;
  candidate: string;
  state: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  classification: string | null;
  manifest_id: string | null;
  error: string | null;
  attempts: number;
  created_at: string;
  updated_at: string;
};

export type NativeSWEbenchResponse = {
  instance_id: string;
  disclosure: string;
  limitation: string;
  audit_limitation: string;
  controls: {
    identity: string;
    case: string;
    role: string;
    native_resolved: boolean;
    adapter_resolved: boolean;
    native_adapter_parity: boolean;
    f2p_explicit_pass: boolean;
    complete_native_evidence: boolean;
    audit_identity: string;
    audit_verdict: "PASS" | "REJECT" | "INCONCLUSIVE";
    audit_checks: Record<string, boolean>;
    candidate_patch_id: string;
    image_identity: string;
    artifacts: Record<string, string>;
    observed_status_map: Record<string, string>;
  }[];
};

export type TrainingPilotsResponse = {
  scope: string;
  preflights: {
    id: string;
    configuration_id: string;
    report_id: string;
    arm: "vulnerable" | "sealed";
    seed: number;
    report_status: "FAILED" | "COMPLETE";
    global_steps: number;
    outcomes: Record<string, number>;
    reward_sum: number;
    samples: number;
    evaluator_failures: number;
    max_gradient_norm: number;
    adapter_identity: string | null;
    objects: number;
    limitation: string;
  }[];
  pilots: {
    id: string;
    configuration_id: string;
    objects: number;
    missing_frozen_source_files?: string[];
    summary: {
      model_snapshot_revision: string;
      paired_conditions_complete: boolean;
      nonzero_within_batch_reward_variance: boolean;
      downstream_improvement_established: boolean;
      limitation: string;
      conditions: {
        arm: "vulnerable" | "sealed";
        seed: number;
        global_steps: number;
        outcomes: Record<string, number>;
        reward_sum: number;
        samples: number;
        train_loss: number;
        adapter_identity: string;
        adapter_bytes: number;
        gpu_name: string;
      }[];
    };
  }[];
};

export type RunEvent = {
  id: number;
  run_id: string;
  kind: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type EvaluationEvidence = {
  candidate_identity: string;
  image_identity: string;
  verdict: string;
  counts: { passed: number; failed: number; skipped: number; errors: number };
  copied_files: string[];
  process: { status: string; exit_code: number | null; stdout: string; stderr: string };
};

export type RunEvidence = {
  schema_version: number;
  candidate_identity: string;
  classification: string;
  proxy: EvaluationEvidence;
  audit: EvaluationEvidence;
  sealed?: EvaluationEvidence;
  source_kind?: "model_tool_run";
  model_run_id?: string;
  model?: {
    served_model: string;
    model_revision: string;
    server_image_identity: string;
    tool_policy: string;
    agent_stopped_reason: string;
    complete_evidence: boolean;
    prompt_tokens: number;
    completion_tokens: number;
    tool_actions: { kind: string; path?: string; command?: string[] }[];
    final_message: string;
  };
};

export type InfluenceResponse = {
  scope: string;
  graph: {
    resolution: string;
    mechanism_status: string;
    nodes: { id: string; kind: string; label: string; owner: string }[];
    edges: { source: string; target: string; relation: string; support: string; evidence_ids: string[]; explanation: string }[];
    finding: { candidate_identity: string; proxy_evidence_id: string; audit_evidence_id: string };
  };
  witness: {
    essential_files: string[];
    query_count: number;
    minimal_within_file_granularity: boolean;
    interventions: { kept_files: string[]; proxy_verdict: string; solution_sha256: string; process_evidence_id: string }[];
  };
};

export type RepairPreviewResponse = {
  scope: string;
  plans: {
    plan: { operator: string; allowed_files: string[]; required_passes: number };
    status: string;
    exploit_blocked: boolean;
    positives_preserved: boolean;
    negatives_preserved: boolean;
    heldout_blocked: boolean;
    repeatable: boolean;
    outcomes: { candidate: string; expected: string; observed: string; passed: boolean }[];
  }[];
};

export type PromotionReviewResponse = {
  disposition: "REJECTED" | "NONDETERMINISTIC" | "UNENFORCEABLE";
  plan_identity: string;
  corpus_identity: string;
  seal_evidence: null;
  gates: { name: string; passed: boolean; detail: string }[];
  controls: {
    name: string;
    role: string;
    native_verdict: string;
    audit_verdict: string;
    repaired_verdict: string;
  }[];
  termination_stress: {
    name: string;
    proxy_verdict: string;
    audit_verdict: string;
    repaired_verdict: string;
    proxy_completed_tests: number;
    repaired_completed_tests: number;
  };
};

export type RepairPlanPreviewResponse = {
  scope: string;
  plan_identity: string;
  parent_policy_identity: string;
  child_policy_identity: string;
  forward_operators: string[];
  inverse_operators: string[];
  policy_rollback_exact: boolean;
  provider_capability_proven: boolean;
  managed_artifact_rollback_proven: boolean;
  seal_evidence: null;
};

export type ManagedRepairResponse = {
  report_id: string;
  source: "verified_saved_execution";
  scope: string;
  disposition: "UNENFORCEABLE";
  seal_evidence: null;
  gates: Record<string, boolean>;
  enforcement_probe: { identity: string; passed: boolean; gates: Record<string, boolean>; limitations: string[] } | null;
  controls: { name: string; role: string; candidate_identity: string; proxy: string; audit: string; sealed: string[] }[];
  stress: { name: string; verdict: string; counts: { passed: number; failed: number } };
  rollback_id: string;
  run_metadata: { started_at_utc: string; finished_at_utc: string; elapsed_seconds: number; evaluations: number; gpu_jobs: number; capability_probe_executions?: number };
  verification: string;
  limitations: string[];
};

export type UpstreamGraderCase = {
  case: string;
  expected_tests: string[];
  observed_status_map: Record<string, string>;
  execution_health: string;
  historical_proxy: {
    source_commit: string;
    source_blob: string;
    verdict: string;
    f2p_success: string[];
    f2p_failure: string[];
    p2p_success: string[];
    p2p_failure: string[];
  };
  repaired_control: {
    source_commit: string;
    source_blob: string;
    verdict: string;
    f2p_success: string[];
    f2p_failure: string[];
    p2p_success: string[];
    p2p_failure: string[];
  };
  classification: string;
  limitation: string;
};

export type UpstreamGraderResponse = {
  scope: string;
  cases: UpstreamGraderCase[];
};

export type SWEbenchCase = {
  case: string;
  upstream_commit: string;
  grading_blob: string;
  parser_blob: string;
  candidate_identity: string;
  solution_sha256: string;
  proxy: { verdict: string; grader_resolution: string; copied_files: string[]; observed_status_map: Record<string, string>; process_evidence_id: string; process: { exit_code: number | null; stdout: string } };
  audit: { verdict: string; grader_resolution: string; copied_files: string[]; observed_status_map: Record<string, string>; process_evidence_id: string; process: { exit_code: number | null; stdout: string } };
  classification: string;
  limitation: string;
};

export type SWEbenchResponse = { scope: string; cases: SWEbenchCase[] };

export type SWEbenchRepairPreview = {
  operator: string;
  disposition: string;
  limitation: string;
  controls: { case: string; proxy_verdict: string; audit_verdict: string; repaired_verdict: string; preserved: boolean }[];
};

export const API_URL = process.env.AUTOSEAL_API_URL ?? "http://127.0.0.1:8000";

export type SftCalibration = {
  archive_id: string; evaluation_id: string; configuration_id: string; adapter_id: string;
  report_id: string; dataset_revision: string; seed: number; resumed_from_step: number; global_step: number;
  attempted_per_phase: number; scope: string; loss_scope: string; max_steps: number;
  training_examples: number; trainable_parameters: number; peak_gpu_bytes: number; gpu: string;
  model_source: { repository: string; revision: string }; scheduler: string;
  phases: Record<"baseline" | "post_sft", { attempted: number; syntax_valid: number; audit_pass: number;
    proxy_pass: number; fixed_wrong_adherent: number; classifications: Record<string, number> }>;
  curve: { step: number; loss: number; grad_norm: number; learning_rate: number }[];
  limitations: string[];
};

export type ModelStudy = {
  evaluation_id: string; training_archive_id: string; generation_archive_id: string;
  manifest_id: string; dataset_revision: string; hidden_commitment: string; starting_checkpoint: string;
  scope: string; verification: string; seeds: number[]; steps_per_condition: number;
  model_source: { repository: string; revision: string };
  paired_adapter_identity: { seed: number; same_adapter_bytes: boolean }[];
  training_conditions: { arm: string; seed: number; status: string; accepted_outputs: number;
    attempted_outputs: number; reward_sum: number; nonconstant_reward_groups: number; adapter_id: string }[];
  summary: { audit_complete: boolean; limitations: string[];
    models: { model_id: string; arm: string; seed: number | null; attempts: number; invalid_outputs: number;
      inconclusive: number; audit_passes: number; proxy_passes: number; false_rewards: number;
      audit_success_rate: number; false_reward_rate_bounds: number[] }[];
    paired_seed_contrasts: { metric: string; direction: string; seed_differences: number[]; mean_difference: number;
      descriptive_seed_bootstrap_95_percentile: number[]; method: string; interpretation_eligible: boolean }[] };
};

export async function fetchApi<T>(path: string): Promise<T> {
  const token = process.env.AUTOSEAL_API_TOKEN;
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store",
    headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!response.ok) throw new Error(`AutoSeal API returned ${response.status}`);
  return response.json() as Promise<T>;
}

export type Workflow = {
  id: string; kind: string; payload: Record<string, string>;
  state: "QUEUED" | "RUNNING" | "CANCEL_REQUESTED" | "COMPLETED" | "FAILED" | "CANCELLED";
  attempts: number; result_id: string | null; error: string | null; created_at: string; updated_at: string;
};

export type ArtifactValidation = {
  validation_id: string; task: { task_id: string; operation: string; proxy_mode: string; origin: string };
  gates: Record<string, boolean>;
  controls: { name: string; role: string; proxy: string; audit: string; sealed: string[] }[];
  search: { candidates?: unknown[]; [key: string]: unknown };
  graph: Record<string, unknown>; parent_revision: string; child_revision: string;
  witness_id: string; rollback_id: string; limitations: string[];
};
