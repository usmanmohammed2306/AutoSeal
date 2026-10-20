import pytest

from autoseal.influence import InfluenceEdge, InfluenceGraph, fixture_influence_graph


def test_fixture_graph_has_intervention_backed_file_influence() -> None:
    graph = fixture_influence_graph("exploit")
    causal = [edge for edge in graph.edges if edge.relation == "AFFECTS_REWARD"]
    assert len(causal) == 1
    assert causal[0].source == "candidate:conftest.py"
    assert causal[0].support == "INTERVENTION"
    assert len(causal[0].evidence_ids) == 2
    assert graph.mechanism_status == "NOT_TRACED"


def test_graph_rejects_unproven_causal_and_dangling_edges() -> None:
    graph = fixture_influence_graph("exploit")
    changed = graph.model_dump(mode="json")
    changed["edges"][-1]["support"] = "OBSERVED"
    with pytest.raises(ValueError, match="intervention evidence"):
        InfluenceGraph.model_validate(changed)
    changed = graph.model_dump(mode="json")
    changed["edges"][-1]["source"] = "unknown"
    with pytest.raises(ValueError, match="unknown node"):
        InfluenceGraph.model_validate(changed)


def test_clean_candidate_is_not_a_false_reward_graph() -> None:
    with pytest.raises(ValueError, match="confirmed false reward"):
        fixture_influence_graph("positive")
