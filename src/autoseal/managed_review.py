"""Read-only product view of a pinned, independently rechecked validation."""

from pathlib import Path

from autoseal.managed_repair import verify_managed_report
from autoseal.result_binding import ResultContext, resolve_result
from autoseal.revisions import RevisionManager
from autoseal.storage import ContentAddressedStore


def managed_review(root: Path, identity: str) -> dict:
    report = verify_managed_report(root, identity)
    store = ContentAddressedStore(root / "evidence")
    manager = RevisionManager(root / "manager", store)

    def evaluation(ref: str) -> dict:
        receipt = store.get_json(ref)
        return resolve_result(store, ref, ResultContext.model_validate(receipt["context"]),
                              channel=receipt["channel"])

    controls = []
    for control in report["controls"]:
        proxy, audit = evaluation(control["proxy"]), evaluation(control["audit"])
        sealed = [evaluation(ref) for ref in control["sealed"]]
        controls.append({"name": control["name"], "role": control["role"],
            "candidate_identity": proxy["candidate_identity"], "proxy": proxy["verdict"],
            "audit": audit["verdict"], "sealed": [r["verdict"] for r in sealed],
            "sealed_counts": [r["counts"] for r in sealed]})
    stress = evaluation(report["unsupported_control"]["result_id"])
    probe = None
    if report.get("enforcement_probe_id"):
        raw_probe = store.get_json(report["enforcement_probe_id"])
        probe = {"identity": report["enforcement_probe_id"], "passed": raw_probe["passed"],
                 "gates": raw_probe["gates"], "limitations": raw_probe["limitations"]}
    return {"report_id": identity, "source": "verified_saved_execution", "scope": report["scope"],
        "enforcement_probe": probe,
        "disposition": report["disposition"], "seal_evidence": None,
        "gates": report["gates"], "controls": controls,
        "stress": {"name": "exit_spoof", "verdict": stress["verdict"], "counts": stress["counts"]},
        "parent_revision": report["parent_revision"], "child_revision": report["child_revision"],
        "image_identity": manager.load(report["parent_revision"]).image_identity,
        "rollback_id": report["rollback_id"], "run_metadata": report["run_metadata"],
        "limitations": report["limitations"],
        "verification": "Raw receipts and candidate snapshots rechecked on this request; no execution or promotion performed."}
