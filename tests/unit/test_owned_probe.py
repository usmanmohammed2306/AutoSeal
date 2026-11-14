"""Protocol interpretation only; the Docker integration supplies runtime proof."""

import json

import pytest

from autoseal.owned_probe import interpret_probe


def observation():
    return {"nonce": "a" * 32, "uid": 65534, "euid": 65534,
        "root_write_denied": True, "candidate_write_denied": True,
        "projected_entries": ["solution.py"], "docker_socket_absent": True,
        "named_credentials_absent": True, "effective_capabilities": 0,
        "no_new_privileges": "1", "seccomp": "2", "ipv4_route_denied": True,
        "ipv6_route_denied": True, "memory_limit": "536870912", "pid_limit": "128",
        "cpu_limit": "100000 100000", "swap_limit": "0"}


def process(body, **updates):
    return {"status": "exited_zero", "stdout": json.dumps(body),
            "stdout_truncated": False, "stderr_truncated": False, **updates}


def test_complete_scoped_observation_is_checked_field_by_field():
    result = interpret_probe(process(observation()), "a" * 32)
    assert result["passed"] and len(result["gates"]) == 17


@pytest.mark.parametrize("key,value", [
    ("uid", 0), ("euid", 0), ("root_write_denied", False), ("candidate_write_denied", False),
    ("projected_entries", ["solution.py", "conftest.py"]), ("docker_socket_absent", False),
    ("named_credentials_absent", False), ("effective_capabilities", 1),
    ("no_new_privileges", "0"), ("seccomp", "0"), ("ipv4_route_denied", False),
    ("ipv6_route_denied", False), ("memory_limit", "max"), ("pid_limit", "max"),
    ("cpu_limit", "max 100000"), ("swap_limit", "max"), ("nonce", "b" * 32),
    ("candidate_write_denied", 1),
])
def test_failed_or_wrong_typed_capability_cannot_pass(key, value):
    body = observation()
    body[key] = value
    result = interpret_probe(process(body), "a" * 32)
    assert result["passed"] is False and result["gates"][key] is False


@pytest.mark.parametrize("updates", [{"status": "timeout"}, {"status": "exited_nonzero"},
                                     {"stdout_truncated": True}, {"stderr_truncated": True}])
def test_incomplete_probes_are_not_successful_enforcement_evidence(updates):
    assert not interpret_probe(process(observation(), **updates), "a" * 32)["passed"]


def test_missing_and_nonobject_observations_fail_closed():
    body = observation()
    del body["root_write_denied"]
    assert not interpret_probe(process(body), "a" * 32)["passed"]
    assert not interpret_probe(process(["PASS"]), "a" * 32)["passed"]
