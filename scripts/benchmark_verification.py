"""Compare identical offline validation with uncached and bounded-snapshot reads.

Measures one local archive, not Docker, inference or concurrent API throughput.
Both variants use the same validation checks, alternating order per repetition.
"""

import argparse
import json
from pathlib import Path
from statistics import median
import time

from autoseal.artifact_pipeline import _verify_artifact_validation, verify_artifact_validation
from autoseal.storage import ContentAddressedStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=10)
    args = parser.parse_args()
    if not 3 <= args.pairs <= 100:
        parser.error("pairs must be between 3 and 100")
    args.root.mkdir(parents=True, exist_ok=False)
    identity = json.loads((args.archive / "validation.json").read_text())["validation_id"]
    pairs = []
    for repeat in range(args.pairs):
        timings, outputs = {}, {}
        for name in (("uncached", "snapshot") if repeat % 2 == 0 else ("snapshot", "uncached")):
            start = time.perf_counter()
            outputs[name] = (_verify_artifact_validation if name == "uncached" else verify_artifact_validation)(
                ContentAddressedStore(args.archive / "evidence"), identity)
            timings[name] = time.perf_counter() - start
        if outputs["uncached"] != outputs["snapshot"] or not all(outputs["snapshot"]["gates"].values()):
            raise ValueError("verification variants disagree or the archive has failed gates")
        pairs.append({"repeat": repeat, "seconds": timings, "same_result": True})
    baseline, snapshot = (median(row["seconds"][name] for row in pairs) for name in ("uncached", "snapshot"))
    store = ContentAddressedStore(args.root / "evidence")
    report = {"kind": "local_validation_verification_comparison", "schema_version": 1,
        "validation_id": identity, "pairs": pairs, "median_uncached_seconds": baseline,
        "median_snapshot_seconds": snapshot, "median_speedup": baseline / snapshot,
        "sources": {str(p): store.put_bytes(p.read_bytes()) for p in [*sorted(Path("src/autoseal").glob("*.py")), Path(__file__)]},
        "limitations": ["One warm local offline archive; alternating-order pairs, same verifier and bytes.",
            "No Docker or model execution timed; no concurrent API, cold-storage or cloud-load result.",
            "Fresh bounded snapshot per verification; corruption and JSON mutation have separate tests."]}
    identity = store.put_json(report)
    (args.root / "report.json").write_text(json.dumps({"report_id": identity}, indent=2) + "\n")
    print(json.dumps({"report_id": identity, "uncached_ms": baseline * 1000,
        "snapshot_ms": snapshot * 1000, "median_speedup": baseline / snapshot}))


if __name__ == "__main__":
    main()
