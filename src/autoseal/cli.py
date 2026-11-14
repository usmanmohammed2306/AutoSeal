"""Command-line interface for AutoSeal."""

import argparse
import json
import os
from pathlib import Path
import time
from typing import Optional, Sequence

from autoseal.conformance import process_evidence_report
from autoseal.docker_fixture import DEFAULT_IMAGE, run_fixture_in_docker
from autoseal.evidence import evidence_id, read_evidence
from autoseal.evaluation import compare_fixture, evaluate_fixture
from autoseal.investigation import finding_from_pair, minimize_fixture
from autoseal.influence import fixture_influence_graph
from autoseal.execution import run_command
from autoseal.model_agent import ModelDeployment, VLLMClient
from autoseal.model_run import record_model_run, load_model_run, replay_model_artifacts
from autoseal.provider_probe import probe_docker_provider
from autoseal.local_demo import demo_report
from autoseal.local_demo import FIXTURE
from autoseal.repair import local_repair_search
from autoseal.repair import RepairOperator, RepairPlan
from autoseal.promotion import review_local_repair
from autoseal.repair_engine import local_composed_policy_preview
from autoseal.storage import ContentAddressedStore, load_comparison, store_comparison
from autoseal.trajectory import load_trajectory, record_scripted_fixture, replay_scripted_fixture
from autoseal.upstream_swesmith import compare_missing_tests_case
from autoseal.upstream_swebench import compare_swebench_case, preview_swebench_f2p_repair


def _non_negative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if not 0 < parsed < float("inf"):
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autoseal",
        description="Inspect command execution as structured evidence.",
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Run one command and print process evidence as JSON.",
    )
    run_parser.add_argument(
        "--max-output-bytes",
        type=_non_negative_integer,
        default=64 * 1024,
        help="Maximum stdout and stderr bytes retained separately.",
    )
    run_parser.add_argument(
        "--cwd",
        type=Path,
        default=None,
        help="Working directory for child process.",
    )
    run_parser.add_argument(
        "--timeout-seconds",
        type=_positive_float,
        default=None,
        help="Maximum time to wait before stopping the child process group.",
    )
    run_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to execute. Place it after --.",
    )

    identity_parser = subparsers.add_parser(
        "evidence-id",
        help="Validate a process result and print its stable identity.",
    )
    identity_parser.add_argument("path", type=Path, help="Path to process evidence JSON.")

    conformance_parser = subparsers.add_parser(
        "conformance", help="Run a named executable acceptance suite."
    )
    conformance_parser.add_argument("suite", choices=["process-evidence"])
    demo_parser = subparsers.add_parser(
        "demo", help="Run the local false-reward and projection-repair demonstration."
    )
    demo_parser.add_argument(
        "--summary", action="store_true", help="Show verdicts and checks without raw Pytest output."
    )
    evaluation_parser = subparsers.add_parser(
        "evaluate", help="Evaluate a checked-in research fixture through one channel."
    )
    evaluation_parser.add_argument("candidate", help="Name of the checked-in fixture candidate.")
    evaluation_parser.add_argument(
        "--channel", choices=["proxy", "audit", "sealed"], required=True
    )
    comparison_parser = subparsers.add_parser(
        "compare", help="Compare proxy and audit over one checked-in candidate."
    )
    comparison_parser.add_argument("candidate", help="Name of the checked-in fixture candidate.")
    comparison_parser.add_argument(
        "--store", type=Path, default=None, help="Persist the comparison in a local evidence store."
    )
    replay_parser = subparsers.add_parser(
        "replay", help="Verify and reopen a stored proxy and audit comparison."
    )
    replay_parser.add_argument("manifest_id", help="Content identity of the comparison manifest.")
    replay_parser.add_argument("--store", type=Path, required=True)
    finding_parser = subparsers.add_parser(
        "finding", help="Confirm a false-reward finding for a checked-in fixture."
    )
    finding_parser.add_argument("candidate")
    minimizer_parser = subparsers.add_parser(
        "minimize", help="Minimize a checked-in false reward at file granularity."
    )
    minimizer_parser.add_argument("candidate")
    minimizer_parser.add_argument("--max-queries", type=_non_negative_integer, default=20)
    graph_parser = subparsers.add_parser(
        "influence", help="Show intervention-backed file influence for a checked-in false reward."
    )
    graph_parser.add_argument("candidate")
    trajectory_parser = subparsers.add_parser(
        "trajectory", help="Record, inspect, or replay a Docker scripted-agent trajectory."
    )
    trajectory_actions = trajectory_parser.add_subparsers(dest="trajectory_action", required=True)
    trajectory_record = trajectory_actions.add_parser("record")
    trajectory_record.add_argument("candidate")
    trajectory_record.add_argument("--store", type=Path, required=True)
    trajectory_show = trajectory_actions.add_parser("show")
    trajectory_show.add_argument("identity")
    trajectory_show.add_argument("--store", type=Path, required=True)
    trajectory_replay = trajectory_actions.add_parser("replay")
    trajectory_replay.add_argument("identity")
    trajectory_replay.add_argument("--store", type=Path, required=True)
    model_parser = subparsers.add_parser("model-run", help="Run a pinned model through Docker tools and three evaluators.")
    model_parser.add_argument("--deployment", type=Path, required=True)
    model_parser.add_argument("--task", type=Path, required=True)
    model_parser.add_argument("--token-file", type=Path)
    model_parser.add_argument("--store", type=Path, required=True)
    model_parser.add_argument("--max-steps", type=int, default=12)
    model_parser.add_argument("--max-total-tokens", type=int, default=12000)
    model_parser.add_argument("--fixed-invalid-solution", action="store_true", help="Explicit targeted-attack condition: mount the checked-in wrong solution read-only.")
    model_replay = subparsers.add_parser("model-replay", help="Re-evaluate a frozen model artifact without resampling the model.")
    model_replay.add_argument("identity")
    model_replay.add_argument("--store", type=Path, required=True)
    provider_probe = subparsers.add_parser("provider-probe", help="Actively measure the scoped Mac Docker research boundary.")
    provider_probe.add_argument("--store", type=Path, required=True)
    reward_worker = subparsers.add_parser("reward-worker", help="Relay trusted Sol training requests to Mac Docker rewards.")
    reward_worker.add_argument("--store", type=Path, required=True)
    reward_worker.add_argument("--manifest-id", required=True)
    reward_worker.add_argument("--exchange-name", required=True)
    reward_worker.add_argument("--once", action="store_true")
    reward_worker.add_argument("--max-seconds", type=_positive_float, default=1800)
    subparsers.add_parser(
        "repair-preview", help="Compare typed repair policies on the local control corpus."
    )
    promotion_parser = subparsers.add_parser(
        "promotion-review", help="Run fail-closed local semantic gates without issuing SealEvidence."
    )
    promotion_parser.add_argument(
        "--operator", choices=[item.value for item in RepairOperator],
        default=RepairOperator.ARTIFACT_PROJECTION.value,
    )
    promotion_parser.add_argument("--required-passes", type=_non_negative_integer, default=0)
    managed = subparsers.add_parser("managed-repair", help="Run and inspect real Mac Docker repair validation and managed rollback.")
    managed_actions = managed.add_subparsers(dest="managed_action", required=True)
    managed_validate = managed_actions.add_parser("validate")
    managed_validate.add_argument("--root", type=Path, required=True, help="New directory for this immutable validation attempt.")
    managed_verify = managed_actions.add_parser("verify")
    managed_verify.add_argument("identity")
    managed_verify.add_argument("--root", type=Path, required=True)
    artifact = subparsers.add_parser("artifact-repair", help="Run registered artifact-output repair, promotion and rollback.")
    artifact_actions = artifact.add_subparsers(dest="artifact_action", required=True)
    artifact_actions.add_parser("cases")
    for action in ("validate", "verify", "promote", "demo"):
        command = artifact_actions.add_parser(action)
        command.add_argument("target", help="Registered case name, or a validation digest for verify/promote.")
        command.add_argument("--root", type=Path, required=True)
    artifact_rollback = artifact_actions.add_parser("rollback")
    artifact_rollback.add_argument("--root", type=Path, required=True)
    artifact_rollback.add_argument("--expected-child", required=True)
    subparsers.add_parser(
        "repair-plan-preview",
        help="Inspect a composed typed plan and exact policy inverse, without a production seal.",
    )
    upstream_parser = subparsers.add_parser(
        "upstream-swesmith",
        help="Replay SWE-Smith's pinned historical missing-test grader defect.",
    )
    upstream_parser.add_argument(
        "case", choices=["collection_failure", "legitimate_solution", "ordinary_failure"]
    )
    swebench_parser = subparsers.add_parser(
        "upstream-swebench",
        help="Reproduce the reported current xfail false reward with a pinned SWE-bench grader.",
    )
    swebench_parser.add_argument("case", choices=["xfail", "xfail_variant", "skip", "clean", "positive", "p2p_xfail"])
    native_parser = subparsers.add_parser("native-swebench", help="Run a reviewed control through the pinned official SWE-bench harness.")
    native_parser.add_argument("case", choices=["gold", "gold_alternative", "clean", "ordinary_invalid", "xfail", "skip", "xfail_variant"])
    native_parser.add_argument("--store", type=Path, required=True)
    native_parser.add_argument("--output-root", type=Path, default=Path(".autoseal/native-runs"))
    native_parser.add_argument("--timeout", type=int, default=300)
    native_audit = subparsers.add_parser("native-swebench-audit", help="Independently check a reviewed native candidate's task behavior.")
    native_audit.add_argument("native_identity", help="Content identity of an archived native SWE-bench case.")
    native_audit.add_argument("--store", type=Path, required=True)
    native_audit.add_argument("--timeout", type=int, default=60)
    subparsers.add_parser(
        "upstream-swebench-repair-preview",
        help="Preview a scoped F2P explicit-pass verifier policy on SWE-bench controls.",
    )
    docker_parser = subparsers.add_parser(
        "docker-fixture", help="Evaluate one checked-in fixture in a restricted Docker container."
    )
    docker_parser.add_argument("candidate")
    docker_parser.add_argument("--channel", choices=["proxy", "audit", "sealed"], required=True)
    docker_parser.add_argument("--image", default=DEFAULT_IMAGE)
    database_parser = subparsers.add_parser(
        "db-init", help="Create local development tables. Use migrations for deployed databases."
    )
    database_parser.add_argument("--database-url", required=True)
    worker_parser = subparsers.add_parser(
        "worker", help="Process persisted fixture runs in a separate worker process."
    )
    worker_parser.add_argument("--database-url", required=True)
    worker_parser.add_argument("--store", type=Path, required=True)
    worker_parser.add_argument("--once", action="store_true")
    worker_parser.add_argument("--workflow-root", type=Path)
    server_parser = subparsers.add_parser("serve", help="Run the local research API.")
    server_parser.add_argument("--database-url", required=True)
    server_parser.add_argument("--store", type=Path, required=True)
    server_parser.add_argument("--port", type=int, default=8000)
    server_parser.add_argument("--managed-report-root", type=Path)
    server_parser.add_argument("--managed-report-id", help="Pinned digest of a retained managed validation report.")
    server_parser.add_argument("--workflow-root", type=Path)
    server_parser.add_argument("--require-auth", action="store_true", help="Require AUTOSEAL_OPERATOR_TOKEN; optionally configure AUTOSEAL_READER_TOKEN.")
    server_parser.add_argument("--shell-archive-root", type=Path)
    server_parser.add_argument("--shell-archive-id")
    server_parser.add_argument("--sft-archive-root", type=Path)
    server_parser.add_argument("--sft-evaluation-id")
    release_parser = subparsers.add_parser("release-check", help="Verify retained evidence and name every open V1 release obligation.")
    release_parser.add_argument("--root", type=Path, required=True, help="Local archive root containing referenced relative directories.")
    release_parser.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.action == "release-check":
        from autoseal.release import ReleaseCandidate, inspect_release
        try:
            candidate = ReleaseCandidate.model_validate_json(arguments.manifest.read_bytes())
            report = inspect_release(arguments.root, candidate)
            print(json.dumps(report, indent=2))
            return 0 if report["release_eligible"] else 1
        except (OSError, ValueError, KeyError, TypeError) as exc:
            parser.exit(2, f"release evidence invalid: {exc}\n")

    if arguments.action == "evaluate":
        try:
            result = evaluate_fixture(arguments.candidate, arguments.channel)
        except ValueError as exc:
            parser.exit(2, f"invalid fixture: {exc}\n")
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "finding":
        try:
            result = finding_from_pair(compare_fixture(arguments.candidate))
        except ValueError as exc:
            parser.exit(2, f"finding not confirmed: {exc}\n")
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "minimize":
        try:
            result = minimize_fixture(
                arguments.candidate, max_queries=arguments.max_queries
            )
        except ValueError as exc:
            parser.exit(2, f"minimization failed: {exc}\n")
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "influence":
        try:
            result = fixture_influence_graph(arguments.candidate)
        except ValueError as exc:
            parser.exit(2, f"influence graph unavailable: {exc}\n")
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "model-run":
        client = None
        try:
            deployment = ModelDeployment.model_validate_json(arguments.deployment.read_text())
            token = arguments.token_file.read_text().strip() if arguments.token_file else None
            client = VLLMClient(deployment, api_key=token)
            store = ContentAddressedStore(arguments.store)
            identity = record_model_run(client, arguments.task.read_text(), store,
                                        max_steps=arguments.max_steps, max_total_tokens=arguments.max_total_tokens,
                                        fixed_solution=(FIXTURE / "candidates/negative/solution.py").read_text() if arguments.fixed_invalid_solution else None)
            record = load_model_run(store, identity)
            print(json.dumps({"model_run_id": identity, "classification": record.classification,
                              "complete_evidence": record.complete_evidence,
                              "agent_stopped_reason": record.agent_stopped_reason,
                              "evaluations": {channel: store.get_json(reference) for channel, reference in record.evaluations.items()}}, indent=2))
            return 0 if record.complete_evidence else 1
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"model run failed: {exc}\n")
        finally:
            if client is not None:
                client.close()

    if arguments.action == "native-swebench":
        try:
            from autoseal.native_swebench import run_native_case, load_native_case
            store = ContentAddressedStore(arguments.store)
            identity = run_native_case(arguments.case, store, output_root=arguments.output_root, timeout=arguments.timeout)
            receipt = load_native_case(store, identity)
            print(json.dumps({"identity": identity, **receipt.model_dump(mode="json")}, indent=2))
            return 0 if receipt.complete_native_evidence and receipt.native_adapter_parity else 1
        except (OSError, RuntimeError, ValueError, ImportError) as exc:
            parser.exit(2, f"native benchmark run failed: {exc}\n")

    if arguments.action == "native-swebench-audit":
        try:
            from autoseal.native_swebench_audit import load_native_audit, run_native_audit
            store = ContentAddressedStore(arguments.store)
            identity = run_native_audit(store, arguments.native_identity, timeout=arguments.timeout)
            receipt = load_native_audit(store, identity)
            print(json.dumps({"identity": identity, **receipt.model_dump(mode="json")}, indent=2))
            return 0 if receipt.verdict != "INCONCLUSIVE" else 1
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"native semantic audit failed: {exc}\n")

    if arguments.action == "model-replay":
        try:
            report = replay_model_artifacts(ContentAddressedStore(arguments.store), arguments.identity)
            print(json.dumps(report, indent=2))
            return 0 if report["matched"] else 1
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"model artifact replay failed: {exc}\n")

    if arguments.action == "reward-worker":
        from autoseal.sol_reward_worker import SolRewardRelay
        try:
            relay = SolRewardRelay(ContentAddressedStore(arguments.store), arguments.manifest_id, arguments.exchange_name)
            deadline = time.monotonic() + arguments.max_seconds
            while time.monotonic() < deadline:
                report = relay.process_one()
                if report is not None:
                    print(json.dumps(report), flush=True)
                    if report["status"] != "COMPLETE":
                        return 1
                if arguments.once:
                    return 0
                if report is None:
                    time.sleep(2)
            return 0
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"reward worker failed: {exc}\n")

    if arguments.action == "provider-probe":
        try:
            store = ContentAddressedStore(arguments.store)
            report = probe_docker_provider(store)
            identity = store.put_json(report)
            print(json.dumps({"report_id": identity, **report}, indent=2))
            return 0 if report["passed"] else 1
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"provider probe failed: {exc}\n")

    if arguments.action == "trajectory":
        store = ContentAddressedStore(arguments.store)
        try:
            if arguments.trajectory_action == "record":
                identity = record_scripted_fixture(arguments.candidate, store)
                print(json.dumps({"trajectory_id": identity}, indent=2))
            elif arguments.trajectory_action == "show":
                print(load_trajectory(store, arguments.identity).model_dump_json(indent=2))
            else:
                report = replay_scripted_fixture(store, arguments.identity)
                print(json.dumps(report, indent=2))
                return 0 if report["matched"] else 1
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"trajectory failed: {exc}\n")
        return 0

    if arguments.action == "repair-preview":
        result = local_repair_search()
        print(json.dumps([item.model_dump(mode="json") for item in result], indent=2))
        return 0

    if arguments.action == "promotion-review":
        operator = RepairOperator(arguments.operator)
        try:
            plan = RepairPlan(
                operator=operator,
                allowed_files=("solution.py",) if operator is RepairOperator.ARTIFACT_PROJECTION else (),
                required_passes=arguments.required_passes,
            )
            result = review_local_repair(plan)
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"promotion review failed: {exc}\n")
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "managed-repair":
        from autoseal.managed_repair import validate_managed_fixture, verify_managed_report
        try:
            identity = (validate_managed_fixture(arguments.root) if arguments.managed_action == "validate"
                        else arguments.identity)
            report = verify_managed_report(arguments.root, identity)
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            parser.exit(2, f"managed validation failed: {exc}\n")
        print(json.dumps({"report_id": identity, "report": report}, indent=2, sort_keys=True))
        # A valid abstention is successfully recorded evidence. It does not
        # mean the proposed repair passed the promotion firewall.
        return 0

    if arguments.action == "artifact-repair":
        from autoseal.artifact_cases import registered_tasks
        from autoseal.artifact_pipeline import (deployment_manager, evaluate_artifact, promote_artifact,
            resolve_artifact, rollback_artifact, validate_artifact_case, verify_artifact_validation)
        tasks = registered_tasks()
        try:
            if arguments.artifact_action == "cases":
                result = {"origin": "seeded", "cases": [task.model_dump(mode="json") for task in tasks.values()]}
            elif arguments.artifact_action == "rollback":
                result = {"rollback_id": rollback_artifact(arguments.root, arguments.expected_child)}
            else:
                store = ContentAddressedStore(arguments.root / "evidence")
                target = arguments.target
                if arguments.artifact_action in {"validate", "demo"}:
                    if target not in tasks:
                        raise ValueError("unknown registered artifact task")
                    target = validate_artifact_case(arguments.root, tasks[target])
                report = verify_artifact_validation(store, target)
                result = {"validation_id": target, "report": report}
                if arguments.artifact_action in {"promote", "demo"}:
                    result["promotion"] = promote_artifact(arguments.root, target)
                if arguments.artifact_action == "demo":
                    case = store.get_json(report["case_id"])
                    candidate = case["controls"][4]["candidate_id"]
                    child = deployment_manager(arguments.root).active()
                    sealed = evaluate_artifact(store, report["case_id"], candidate, child, "sealed")
                    result["sealed_verdict"] = resolve_artifact(store, sealed, case_id=report["case_id"], candidate_id=candidate,
                        revision_id=child, channel="sealed")["verdict"]
                    result["production_rollback_id"] = rollback_artifact(arguments.root, child)
                    restored = evaluate_artifact(store, report["case_id"], candidate, report["parent_revision"], "proxy")
                    result["restored_verdict"] = resolve_artifact(store, restored, case_id=report["case_id"], candidate_id=candidate,
                        revision_id=report["parent_revision"], channel="proxy")["verdict"]
                    result["reactivation"] = promote_artifact(arguments.root, target)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            parser.exit(2, f"artifact repair failed: {exc}\n")

    if arguments.action == "repair-plan-preview":
        print(json.dumps(local_composed_policy_preview(), indent=2))
        return 0

    if arguments.action == "upstream-swesmith":
        result = compare_missing_tests_case(arguments.case)
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "upstream-swebench":
        result = compare_swebench_case(arguments.case)
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "upstream-swebench-repair-preview":
        result = preview_swebench_f2p_repair()
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "docker-fixture":
        try:
            result = run_fixture_in_docker(
                arguments.candidate, arguments.channel, image=arguments.image
            )
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"Docker fixture failed: {exc}\n")
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0

    if arguments.action == "db-init":
        from autoseal.db import Base, make_session_factory
        sessions = make_session_factory(arguments.database_url)
        Base.metadata.create_all(sessions.kw["bind"])
        print("local development tables ready")
        return 0

    if arguments.action == "worker":
        from autoseal.db import make_session_factory
        from autoseal.service import RunService
        from autoseal.workflows import WorkflowService
        sessions = make_session_factory(arguments.database_url)
        store = ContentAddressedStore(arguments.store)
        service = RunService(sessions, store)
        workflows = WorkflowService(sessions, store, arguments.workflow_root or
            arguments.store.parent / (arguments.store.name + "-workflows"))
        while True:
            row = workflows.process_one()
            kind = "workflow"
            if row is None:
                row, kind = service.process_one(), "run"
            if row is not None:
                print(json.dumps({"id": row.id, "state": row.state, "kind": kind}), flush=True)
            if arguments.once:
                return 0
            if row is None:
                time.sleep(1)

    if arguments.action == "serve":
        import uvicorn
        from autoseal.api import create_app

        if arguments.require_auth and not os.environ.get("AUTOSEAL_OPERATOR_TOKEN"):
            parser.error("--require-auth needs AUTOSEAL_OPERATOR_TOKEN in the environment")
        uvicorn.run(
            create_app(arguments.database_url, arguments.store,
                       managed_report_root=arguments.managed_report_root,
                       managed_report_identity=arguments.managed_report_id,
                       workflow_root=arguments.workflow_root,
                       shell_archive_root=arguments.shell_archive_root,
                       shell_archive_identity=arguments.shell_archive_id,
                       sft_archive_root=arguments.sft_archive_root,
                       sft_evaluation_identity=arguments.sft_evaluation_id,
                       operator_token=os.environ.get("AUTOSEAL_OPERATOR_TOKEN"),
                       reader_token=os.environ.get("AUTOSEAL_READER_TOKEN")),
            host="127.0.0.1",
            port=arguments.port,
        )
        return 0

    if arguments.action == "compare":
        try:
            result = compare_fixture(arguments.candidate)
        except ValueError as exc:
            parser.exit(2, f"invalid fixture: {exc}\n")
        if arguments.store is None:
            print(result.model_dump_json(indent=2))
        else:
            manifest_id = store_comparison(ContentAddressedStore(arguments.store), result)
            print(json.dumps({"classification": result.classification, "manifest_id": manifest_id}, indent=2))
        return 0

    if arguments.action == "replay":
        try:
            result = load_comparison(
                ContentAddressedStore(arguments.store), arguments.manifest_id
            )
        except (OSError, ValueError) as exc:
            parser.exit(2, f"invalid stored comparison: {exc}\n")
        print(result.model_dump_json(indent=2))
        return 0

    if arguments.action == "demo":
        report = demo_report()
        if arguments.summary:
            report = {
                "status": report["status"],
                "repair_operator": report["repair_operator"],
                "checks": report["checks"],
                "cases": {
                    name: {channel: result["verdict"] for channel, result in channels.items()}
                    for name, channels in report["cases"].items()
                },
            }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "pass" else 1

    if arguments.action == "conformance":
        report = process_evidence_report()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "pass" else 1

    if arguments.action == "evidence-id":
        try:
            print(evidence_id(read_evidence(arguments.path)))
        except (OSError, ValueError) as exc:
            parser.exit(2, f"invalid evidence: {exc}\n")
        return 0

    command = list(arguments.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("run requires a command after --")

    result = run_command(
        command,
        cwd=arguments.cwd,
        max_output_bytes=arguments.max_output_bytes,
        timeout_seconds=arguments.timeout_seconds,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))

    # The CLI successfully produced evidence even when the child failed.
    # Consumers must inspect status and exit_code instead of the CLI exit code.
    return 0
