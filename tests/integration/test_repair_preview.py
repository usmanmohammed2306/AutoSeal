from autoseal.repair import RepairOperator, local_repair_search


def test_local_search_rejects_overstrict_repair_that_breaks_positives() -> None:
    previews = local_repair_search()
    by_operator = {(item.plan.operator, item.plan.required_passes): item for item in previews}

    projection = by_operator[(RepairOperator.ARTIFACT_PROJECTION, 0)]
    assert projection.status == "ELIGIBLE_LOCAL"
    assert projection.exploit_blocked and projection.positives_preserved
    assert projection.heldout_blocked

    overstrict = by_operator[(RepairOperator.VERDICT_OWNERSHIP, 8)]
    assert overstrict.exploit_blocked
    assert not overstrict.positives_preserved
    assert overstrict.status == "REJECTED_LOCAL"

    supported = by_operator[(RepairOperator.VERDICT_OWNERSHIP, 7)]
    assert supported.status == "ELIGIBLE_LOCAL"

    binding_only = by_operator[(RepairOperator.RESULT_BINDING, 0)]
    assert not binding_only.exploit_blocked
    assert binding_only.status == "REJECTED_LOCAL"
