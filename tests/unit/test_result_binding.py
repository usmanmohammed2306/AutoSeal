import pytest

from autoseal.result_binding import ResultContext, BoundResultCache, bind_result, resolve_result
from autoseal.storage import ContentAddressedStore, IntegrityError


def context():
    return ResultContext(**{name: "sha256:" + str(index) * 64 for index, name in
                           enumerate(("task", "candidate", "verifier", "policy", "provider", "environment"))})


def evaluation(ctx):
    return {"candidate_identity": ctx.candidate, "channel": "sealed", "verdict": "PASS",
            "counts": {"passed": 7, "failed": 0, "skipped": 0, "errors": 0},
            "process": {"schema_version": 1, "command": ["pytest"], "status": "exited_zero",
                        "exit_code": 0, "stdout": "7 passed", "stderr": "",
                        "stdout_truncated": False, "stderr_truncated": False,
                        "error_message": None, "elapsed_seconds": 0.1, "timeout_seconds": 10}}


@pytest.mark.parametrize("field", ["task", "candidate", "verifier", "policy", "provider", "environment"])
def test_all_six_context_dimensions_prevent_stale_result_reuse(tmp_path, field):
    store = ContentAddressedStore(tmp_path)
    ctx = context()
    identity = bind_result(store, ctx, evaluation(ctx))
    assert resolve_result(store, identity, ctx, channel="sealed")["verdict"] == "PASS"
    wrong = ctx.model_copy(update={field: "sha256:" + "f" * 64})
    with pytest.raises(IntegrityError, match="binding"):
        resolve_result(store, identity, wrong, channel="sealed")
    with pytest.raises(IntegrityError, match="binding"):
        resolve_result(store, identity, ctx, channel="audit")


def test_cache_cannot_return_wrong_revision_and_refuses_corrupt_process(tmp_path):
    store = ContentAddressedStore(tmp_path)
    ctx = context()
    cache = BoundResultCache(store, max_entries=1)
    identity = cache.put(ctx, evaluation(ctx))
    assert cache.get(ctx, channel="sealed")["counts"]["passed"] == 7
    next_ctx = ctx.model_copy(update={"environment": "sha256:" + "f" * 64})
    assert cache.get(next_ctx, channel="sealed") is None
    cache.put(next_ctx, evaluation(next_ctx))
    assert cache.get(ctx, channel="sealed") is None
    forged = store.get_json(identity)
    forged["process_id"] = store.put_json({"unrelated": True})
    with pytest.raises(IntegrityError, match="summary"):
        resolve_result(store, store.put_json(forged), ctx, channel="sealed")


def test_process_crash_is_not_reclassified_as_an_exploit_block(tmp_path):
    ctx = context()
    item = evaluation(ctx)
    item["verdict"] = "REJECT"
    item["counts"]["passed"] = 0
    with pytest.raises(IntegrityError, match="rejection"):
        bind_result(ContentAddressedStore(tmp_path), ctx, item)
