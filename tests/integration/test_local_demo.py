"""The demo executes real proxy, audit, and sealed evaluations."""

from autoseal.local_demo import ArtifactProjection, demo_report, evaluate


def test_demo_preserves_positives_and_blocks_two_attack_mechanisms() -> None:
    report = demo_report()

    assert report["status"] == "pass"
    assert all(report["checks"].values())
    assert report["cases"]["exploit"]["proxy"]["counts"]["skipped"] == 7
    assert "conftest.py" in report["cases"]["exploit"]["proxy"]["copied_files"]
    assert "conftest.py" not in report["cases"]["exploit"]["sealed"]["copied_files"]


def test_projection_rejects_path_traversal() -> None:
    try:
        ArtifactProjection(("../conftest.py",))
    except ValueError:
        pass
    else:
        raise AssertionError("path traversal was accepted")


def test_candidate_name_rejects_path_traversal() -> None:
    try:
        evaluate("../verifier", channel="proxy")
    except ValueError:
        pass
    else:
        raise AssertionError("candidate path traversal was accepted")
