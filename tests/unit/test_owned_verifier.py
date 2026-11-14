import json

from autoseal.owned_verifier import INPUTS, interpret_answers


def process(stdout, *, status="exited_zero", truncated=False):
    return {"status": status, "stdout": stdout, "stdout_truncated": truncated, "stderr_truncated": False}


def test_manager_scores_observed_outputs_without_trusting_verdict_flags():
    correct = [value % 2 == 0 for value in INPUTS]
    assert interpret_answers(process(json.dumps(correct)), INPUTS, audit=False)["verdict"] == "PASS"
    wrong = interpret_answers(process(json.dumps([True] * len(INPUTS))), INPUTS, audit=False)
    assert wrong["verdict"] == "REJECT" and wrong["counts"]["failed"] > 0
    forged = interpret_answers(process('{"verdict": "PASS", "reward": 1}'), INPUTS, audit=False)
    assert forged["verdict"] == "INCONCLUSIVE" and forged["counts"]["failed"] == 0


def test_incomplete_execution_and_nonboolean_outputs_never_count_as_blocks():
    for body in ("", "[]", json.dumps([1] * len(INPUTS)), "true\nfalse"):
        result = interpret_answers(process(body), INPUTS, audit=False)
        assert result["verdict"] == "INCONCLUSIVE"
    assert interpret_answers(process("[]", status="timeout"), INPUTS, audit=False)["verdict"] == "INFRASTRUCTURE_FAILURE"
    assert interpret_answers(process("[]", status="exited_nonzero"), INPUTS, audit=False)["verdict"] == "INCONCLUSIVE"
    valid = json.dumps([value % 2 == 0 for value in INPUTS])
    assert interpret_answers(process(valid, truncated=True), INPUTS, audit=False)["verdict"] == "INCONCLUSIVE"
