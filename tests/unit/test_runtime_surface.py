import copy

import pytest

from autoseal.runtime_surface import compare_runtime_surfaces


def surfaces():
    body = {"Image": "sha256:image", "Config": {"User": "65534:65534", "Env": ["PATH=/usr/bin"]},
            "HostConfig": {"ReadonlyRootfs": True, "NetworkMode": "none", "CapDrop": ["ALL"],
                           "Privileged": False, "SecurityOpt": ["no-new-privileges"], "IpcMode": "private",
                           "Memory": 512, "PidsLimit": 128, "NanoCpus": 1000},
            "Mounts": [{"Type": "bind", "Destination": "/workspace", "RW": False}]}
    parent = {"container_inspection": body, "image_identity": body["Image"],
              "copied_files": ["solution.py", "tests/test_solution.py"], "source_identity": "sha256:source"}
    child = copy.deepcopy(parent)
    child["container_inspection"]["Mounts"][0]["Destination"] = "/candidate"
    child["projected_files"] = ["solution.py"]
    return parent, child


@pytest.mark.parametrize("key,value,gate", [
    ("NetworkMode", "host", "network_and_trusted_api"),
    ("Privileged", True, "capabilities"),
    ("CapAdd", ["SYS_ADMIN"], "capabilities"),
    ("Tmpfs", {"/new": "rw"}, "write_surface"),
    ("PidMode", "host", "devices_and_namespaces"),
    ("Devices", [{"PathOnHost": "/dev/fake"}], "devices_and_namespaces"),
    ("Memory", 1024, "resource_limits"),
])
def test_actual_rights_increase_fails_comparison(key, value, gate):
    parent, child = surfaces()
    assert all(compare_runtime_surfaces(parent, child).values())
    child["container_inspection"]["HostConfig"][key] = value
    assert compare_runtime_surfaces(parent, child)[gate] is False


def test_new_mount_or_changed_source_cannot_claim_projection():
    parent, child = surfaces()
    child["source_identity"] = "sha256:changed"
    assert compare_runtime_surfaces(parent, child)["read_projection"] is False
    child["source_identity"] = parent["source_identity"]
    child["container_inspection"]["Mounts"].append({"Type": "bind", "Destination": "/manager", "RW": True})
    assert compare_runtime_surfaces(parent, child)["read_projection"] is False
