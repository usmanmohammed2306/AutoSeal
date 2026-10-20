"""Reproduce one disclosed SWE-bench Pro answer leak in a pinned image.

This is a read-only inspection of one reviewed public task image. It does not
run candidate code, measure model exploitation, or promote an environment fix.
"""

from __future__ import annotations

import subprocess
import re
from pathlib import Path
import hashlib


IMAGE = (
    "jefzda/sweap-images@"
    "sha256:aa7fe7a0d2517293b6d689572867a2da18dd702cb418ffa586f758608f491ac6"
)
FIX_COMMIT = "41dfec20bfe9b62cddbbbf621bef2e9aa9685157"
TASK_HEAD = "d5d1ec775caf2d3c9132122c1243898e99fdb2da"
TASK_TREE = "17ec485712222c12d9d849069d58d27bad9278e3"
ISSUE = "https://github.com/scaleapi/SWE-bench_Pro-os/issues/93"
FOCUSED_TEST = "test/utils/AutoDiscoveryUtils-test.tsx"
SEALED_IMAGE = "autoseal/swebench-pro-history-sealed:task-d5d1ec7"
DOCKERFILE = Path(__file__).resolve().parents[2] / "docker/swebench_pro_history_seal.Dockerfile"
AUDIT_DOCKERFILE = Path(__file__).resolve().parents[2] / "examples/upstream_swebench_pro/semantic_audit.Dockerfile"
AUDIT_SOURCE = AUDIT_DOCKERFILE.parent / "AutoSealDelegatedAuth-audit-test.tsx"
AUDIT_TEST = "test/utils/AutoSealDelegatedAuth-audit-test.tsx"
AUDIT_TAGS = {
    "original_baseline": "autoseal/swebench-pro-audit:original-baseline",
    "sealed_baseline": "autoseal/swebench-pro-audit:sealed-baseline",
    "original_gold": "autoseal/swebench-pro-audit:original-gold",
    "sealed_gold": "autoseal/swebench-pro-audit:sealed-gold",
}

DOCKER_BOUNDARY = (
    "docker", "run", "--rm", "--pull", "never", "--platform", "linux/amd64",
    "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--pids-limit", "64",
    "--memory", "1536m", "--cpus", "2", "--user", "0:0",
)


def _run(command: tuple[str, ...], *, timeout: int = 90) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        detail = (result.stderr + "\n" + result.stdout).strip()[-1000:]
        raise RuntimeError(f"pinned image probe failed ({result.returncode}): {detail}")
    return result.stdout.strip()


def _git(*args: str) -> str:
    command = DOCKER_BOUNDARY + ("--entrypoint", "/usr/bin/git", IMAGE, "-C", "/app", *args)
    return _run(command)


def reproduce_history_leak() -> dict:
    """Fail unless the pinned task and an ephemeral history-free tree match."""

    # A missing image must not trigger an implicit multi-gigabyte download.
    _run(("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"))
    head = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    fix_parent = _git("rev-parse", f"{FIX_COMMIT}^")
    fix_subject = _git("show", "-s", "--format=%s", FIX_COMMIT)
    future_count = int(_git("rev-list", "--count", "HEAD..origin/HEAD"))
    if head != TASK_HEAD or tree != TASK_TREE or fix_parent != head or future_count < 1:
        raise RuntimeError("pinned image no longer matches the reviewed leak case")

    # A file:// shallow fetch transfers only the current task commit and tree.
    # /tmp is a bounded container tmpfs. Nothing is written to the image or host.
    projection_script = (
        "git init -q /tmp/clean; "
        "git -C /tmp/clean fetch -q --no-tags --depth=1 file:///app HEAD; "
        "git -C /tmp/clean rev-parse FETCH_HEAD^{tree}; "
        f"if git -C /tmp/clean cat-file -e {FIX_COMMIT}; then "
        "printf 'FUTURE_COMMIT_PRESENT\\n'; exit 1; fi; "
        "printf 'FUTURE_COMMIT_ABSENT\\n'"
    )
    projection = _run(
        DOCKER_BOUNDARY + ("--tmpfs", "/tmp:rw,nosuid,nodev,size=1024m",
                           "--entrypoint", "/bin/sh", IMAGE, "-ec", projection_script)
    ).splitlines()
    if projection != [tree, "FUTURE_COMMIT_ABSENT"]:
        raise RuntimeError("history-free projection changed the task tree or retained the fix")
    return {
        "schema_version": 1,
        "scope": "one disclosed SWE-bench Pro image; Git-history inspection only",
        "original_report": ISSUE,
        "image": IMAGE,
        "task_head": head,
        "task_tree": tree,
        "fix_commit": FIX_COMMIT,
        "fix_parent_is_task_head": True,
        "fix_subject": fix_subject,
        "future_commits_reachable_from_origin_head": future_count,
        "history_free_projection_tree_matches": True,
        "history_free_projection_excludes_fix": True,
        "limitations": [
            "The original reporter discovered the leak and proposed an upstream fix.",
            "No model trajectory or native SWE-bench Pro score was evaluated here.",
            "The projected Git tree was checked, but a full working-tree or test-suite parity run was not.",
            "The projection is an ephemeral proof, not an issued AutoSeal repair.",
        ],
    }


def _focused_test_count(output: str) -> int:
    """Require Jest to report a fully passing, nonempty focused test set."""

    match = re.search(r"Tests:\s+(\d+) passed,\s+(\d+) total", output)
    if match is None or int(match.group(1)) < 1 or match.group(1) != match.group(2):
        raise RuntimeError("focused task tests did not all pass")
    if "Test Suites: 1 passed, 1 total" not in output:
        raise RuntimeError("focused task suite did not pass")
    return int(match.group(1))


def reproduce_workspace_projection() -> dict:
    """Check full-tree preservation, but do not call this an agent-facing seal.

    A read-only original image is used for the baseline. The projected checkout
    is materialized in tmpfs. Its test-only node_modules link points into the
    original image, so this experiment cannot establish history isolation for
    a candidate agent. A separate image without the original .git is required.
    """

    _run(("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"))
    if _git("rev-parse", "HEAD") != TASK_HEAD:
        raise RuntimeError("pinned task HEAD changed")
    if _git("rev-parse", "HEAD^{tree}") != TASK_TREE:
        raise RuntimeError("pinned task tree changed")

    jest = (
        "node ./node_modules/jest/bin/jest.js " + FOCUSED_TEST
        + " --runInBand --no-coverage --cacheDirectory=/tmp/jest-cache"
    )
    baseline = _run(
        DOCKER_BOUNDARY + (
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=1024m",
            "--tmpfs", "/app/coverage:rw,nosuid,nodev,size=16m",
            "--entrypoint", "/bin/sh", IMAGE,
            "-ec", "cd /app; " + jest + " 2>&1",
        )
    )
    baseline_count = _focused_test_count(baseline)

    projection_script = (
        "git init -q /tmp/clean; "
        "git -C /tmp/clean fetch -q --no-tags --depth=1 file:///app HEAD; "
        "git -C /tmp/clean checkout -q --detach FETCH_HEAD; "
        f'test "$(git -C /tmp/clean rev-parse HEAD^{{tree}})" = {TASK_TREE}; '
        'test "$(git -C /tmp/clean status --porcelain)" = ""; '
        f"if git -C /tmp/clean cat-file -e {FIX_COMMIT} 2>/dev/null; then exit 9; fi; "
        f"test -f /tmp/clean/{FOCUSED_TEST}; "
        # This link is only for a preservation test. It is not agent isolation.
        "ln -s /app/node_modules /tmp/clean/node_modules; "
        "cd /tmp/clean; " + jest + " 2>&1; "
        "printf 'PROJECTED_WORKSPACE_PASS\\n'"
    )
    projected_boundary = list(DOCKER_BOUNDARY)
    projected_boundary[projected_boundary.index("--memory") + 1] = "2048m"
    projected = _run(
        tuple(projected_boundary) + (
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=1536m",
            "--entrypoint", "/bin/sh", IMAGE, "-ec", projection_script,
        )
    )
    projected_count = _focused_test_count(projected)
    if "PROJECTED_WORKSPACE_PASS" not in projected.splitlines():
        raise RuntimeError("projected workspace did not finish its checks")
    if projected_count != baseline_count:
        raise RuntimeError("focused test count changed after projection")

    return {
        "schema_version": 1,
        "scope": "one disclosed task; full-tree projection and focused baseline parity",
        "original_report": ISSUE,
        "image": IMAGE,
        "task_head": TASK_HEAD,
        "task_tree": TASK_TREE,
        "fix_commit": FIX_COMMIT,
        "projected_checkout_clean_before_test": True,
        "projected_checkout_tree_matches": True,
        "projected_checkout_excludes_fix": True,
        "focused_test": FOCUSED_TEST,
        "baseline_passed_tests": baseline_count,
        "projected_passed_tests": projected_count,
        "agent_facing_seal": False,
        "limitations": [
            "The original reporter discovered the answer leak.",
            "The test-only dependency link exposes the original image, including its Git history.",
            "This is not a candidate-accessible sealed image or a native benchmark score.",
            "Only one focused test suite was checked, not all legitimate solutions.",
            "No model trajectory, independent task audit, held-out attack, or promotion was run.",
        ],
    }


def build_and_check_sealed_image() -> dict:
    """Build a task-head-only image and test its focused preserved behavior.

    This is a case-specific prototype. It does not execute an agent or certify
    the general AutoSeal promotion firewall. The image is kept locally for
    later candidate runs, and its identity is included in the report.
    """

    _run(("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"))
    _run((
        "docker", "build", "--platform", "linux/amd64", "--network", "none",
        "--pull=false", "--file",
        str(DOCKERFILE), "--tag", SEALED_IMAGE, str(DOCKERFILE.parent),
    ), timeout=240)
    return check_sealed_image()


def check_sealed_image() -> dict:
    """Recheck an already built image without modifying Docker image state."""

    image_identity = _run(("docker", "image", "inspect", SEALED_IMAGE,
                           "--format", "{{.Id}}"))
    if not image_identity.startswith("sha256:"):
        raise RuntimeError("derived image lacks a content identity")

    # The candidate-facing check has no link or mount back to the original.
    boundary = list(DOCKER_BOUNDARY)
    boundary[boundary.index("--memory") + 1] = "2048m"
    check = (
        f'test "$(git -C /app rev-parse HEAD)" = {TASK_HEAD}; '
        f'test "$(git -C /app rev-parse HEAD^{{tree}})" = {TASK_TREE}; '
        'test "$(git -C /app rev-list --all --count)" = 1; '
        'test "$(git -C /app status --porcelain)" = ""; '
        f"if git -C /app cat-file -e {FIX_COMMIT} 2>/dev/null; then exit 9; fi; "
        "test ! -e /tmp/autoseal-shallow; "
        f"test ! -e /app/{AUDIT_TEST}; "
        f"cd /app; node ./node_modules/jest/bin/jest.js {FOCUSED_TEST} "
        "--runInBand --no-coverage --cacheDirectory=/tmp/jest-cache 2>&1; "
        "printf 'SEALED_IMAGE_CHECK_PASS\\n'"
    )
    output = _run(tuple(boundary) + (
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=1024m",
        "--tmpfs", "/app/coverage:rw,nosuid,nodev,size=16m",
        "--entrypoint", "/bin/sh", SEALED_IMAGE, "-ec", check,
    ))
    count = _focused_test_count(output)
    if "SEALED_IMAGE_CHECK_PASS" not in output.splitlines():
        raise RuntimeError("derived image check did not finish")
    return {
        "schema_version": 1,
        "scope": "one disclosed task; derived history-free image prototype",
        "original_report": ISSUE,
        "source_image": IMAGE,
        "sealed_image": SEALED_IMAGE,
        "sealed_image_identity": image_identity,
        "task_head": TASK_HEAD,
        "task_tree": TASK_TREE,
        "fix_commit": FIX_COMMIT,
        "all_refs_commit_count": 1,
        "named_future_fix_absent": True,
        "working_tree_clean_before_test": True,
        "focused_test": FOCUSED_TEST,
        "focused_passed_tests": count,
        "known_original_git_database_removed": True,
        "limitations": [
            "The original reporter discovered the answer leak.",
            "Only the named future fix and reachable Git refs were checked; no exhaustive filesystem scan was made.",
            "Focused task-test preservation is not a full semantic audit.",
            "No coding agent, native benchmark score, valid alternatives, or held-out variants were run.",
            "This prototype has not passed AutoSeal's promotion firewall or rollback gates.",
        ],
    }


def _parse_jest_totals(output: str) -> tuple[int, int, int]:
    match = re.search(
        r"Tests:\s+(?:(\d+) failed,\s+)?(?:(\d+) passed,\s+)?(\d+) total",
        output,
    )
    if match is None:
        raise RuntimeError("Jest did not provide a decisive test total")
    failed, passed, total = (int(value or 0) for value in match.groups())
    if total < 1 or failed + passed != total:
        raise RuntimeError("Jest test totals are incomplete")
    return failed, passed, total


def build_semantic_audit_images() -> None:
    """Build four offline audit-only controls from two pinned task environments."""

    _run(("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"))
    _run(("docker", "image", "inspect", SEALED_IMAGE, "--format", "{{.Id}}"))
    for key, tag in AUDIT_TAGS.items():
        base = SEALED_IMAGE if key.startswith("sealed_") else IMAGE
        target = "gold" if key.endswith("_gold") else "baseline"
        _run((
            "docker", "build", "--platform", "linux/amd64", "--network", "none",
            "--pull=false", "--build-arg", f"TASK_IMAGE={base}",
            "--target", target, "--file", str(AUDIT_DOCKERFILE),
            "--tag", tag, str(AUDIT_DOCKERFILE.parent),
        ), timeout=240)


def check_semantic_audit_matrix() -> dict:
    """Require the baseline to fail the audit and the public gold fix to pass.

    The candidate-facing images never contain this audit test. Each audit-only
    image is tested separately under the same restricted Docker boundary.
    """

    outcomes: dict[str, dict] = {}
    audit_digest = hashlib.sha256(AUDIT_SOURCE.read_bytes()).hexdigest()
    for key, image in AUDIT_TAGS.items():
        image_identity = _run(("docker", "image", "inspect", image,
                               "--format", "{{.Id}}"))
        if not image_identity.startswith("sha256:"):
            raise RuntimeError(f"{key} lacks an image identity")
        boundary = list(DOCKER_BOUNDARY)
        boundary[boundary.index("--memory") + 1] = "2048m"
        command = tuple(boundary) + (
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=1024m",
            "--tmpfs", "/app/coverage:rw,nosuid,nodev,size=16m",
            "--entrypoint", "/bin/sh", image, "-ec",
            f'test "$(sha256sum /app/{AUDIT_TEST} | cut -d " " -f1)" = {audit_digest}; '
            "cd /app; node ./node_modules/jest/bin/jest.js "
            f"{AUDIT_TEST} {FOCUSED_TEST} --runInBand --no-coverage "
            "--cacheDirectory=/tmp/jest-cache",
        )
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=90, check=False)
        output = result.stdout + "\n" + result.stderr
        failed, passed, total = _parse_jest_totals(output)
        expected = (0, 13, 13) if key.endswith("_gold") else (1, 12, 13)
        if (failed, passed, total) != expected:
            raise RuntimeError(f"{key} changed its task/audit test outcome: {(failed, passed, total)}")
        expected_exit = 0 if key.endswith("_gold") else 1
        if result.returncode != expected_exit:
            raise RuntimeError(f"{key} exited {result.returncode}, expected {expected_exit}")
        outcomes[key] = {
            "audit_image": image,
            "audit_image_identity": image_identity,
            "exit_code": result.returncode,
            "failed_tests": failed,
            "passed_tests": passed,
            "total_tests": total,
            "audit_verdict": "PASS" if expected_exit == 0 else "REJECT",
        }

    return {
        "schema_version": 1,
        "scope": "one disclosed task; four-way focused semantic-audit control matrix",
        "source_image": IMAGE,
        "candidate_facing_sealed_image": SEALED_IMAGE,
        "audit_test": AUDIT_TEST,
        "original_focused_test": FOCUSED_TEST,
        "reviewed_gold_source_commit": FIX_COMMIT,
        "audit_source_sha256": audit_digest,
        "audit_recipe_sha256": hashlib.sha256(AUDIT_DOCKERFILE.read_bytes()).hexdigest(),
        "outcomes": outcomes,
        "limitations": [
            "The original reporter discovered the answer leak and the gold patch is the public upstream fix.",
            "The audit was separately authored after inspecting the public fix and is not blind or hidden from future agents.",
            "This is focused Jest evaluation, not the native SWE-bench Pro grader.",
            "Only one public positive and one unsolved baseline are compared in each environment.",
            "No model agent, held-out re-attack, promotion firewall, or general security claim is established.",
        ],
    }
