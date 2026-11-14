"""Run all registered authored cases; retain failures as well as successes.

This is a seeded fixed-output corpus. Its denominator must never be combined
with confirmed external cases or reported as model-generated exploit discovery.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time

from autoseal.artifact_cases import registered_tasks
from autoseal.artifact_pipeline import promote_artifact, validate_artifact_case, verify_artifact_validation
from autoseal.storage import ContentAddressedStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    started, clock = datetime.now(timezone.utc).isoformat(), time.monotonic()
    rows = []
    for identity, task in registered_tasks().items():
        root = args.root / identity
        try:
            validation_id = validate_artifact_case(root, task)
            store = ContentAddressedStore(root / "evidence")
            checked = verify_artifact_validation(store, validation_id)
            promotion = promote_artifact(root, validation_id)
            row = {"case": identity, "origin": "seeded", "operation": task.operation, "proxy_mode": task.proxy_mode,
                "status": "PASSED", "validation_id": validation_id, "gates": checked["gates"], "promotion": promotion}
        except Exception as exc:
            row = {"case": identity, "origin": "seeded", "status": "FAILED", "error": f"{type(exc).__name__}: {exc}"}
        rows.append(row)
        print(json.dumps(row), flush=True)
        (args.root / "progress.json").write_text(json.dumps(rows, indent=2) + "\n")
    store = ContentAddressedStore(args.root / "evidence")
    report = {"kind": "authored_artifact_corpus_validation", "schema_version": 1,
        "status": "PASSED" if all(row["status"] == "PASSED" for row in rows) else "FAILED",
        "started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": time.monotonic() - clock, "cases": rows,
        "sources": {str(p): store.put_bytes(p.read_bytes()) for p in sorted(Path("src/autoseal").glob("*.py"))},
        "limitations": ["Eight deliberately authored cases; four proxy mechanisms and four finite output operations.",
            "Search-excluded variants are committed controls, not blind attacks or fresh model discoveries.",
            "No external-case, benchmark-wide, training-efficacy or hostile-container-escape claim."]}
    identity = store.put_json(report)
    (args.root / "report.json").write_text(json.dumps({"report_id": identity}, indent=2) + "\n")
    print(json.dumps({"report_id": identity, "status": report["status"], "passed": sum(r["status"] == "PASSED" for r in rows), "total": len(rows)}))
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
