"""Compare observed Docker restrictions for this registered fixture provider.

The daemon inspections are trusted inputs. This comparison covers the listed
Docker rights and projected file identities, not kernel escape resistance.
"""

from __future__ import annotations


def compare_runtime_surfaces(parent: dict, child: dict) -> dict[str, bool]:
    before, after = parent["container_inspection"], child["container_inspection"]
    bh, ah = before["HostConfig"], after["HostConfig"]
    bm, am = before.get("Mounts", []), after.get("Mounts", [])
    # The child sees only the same solution bytes that the parent received.
    # No manager, audit, result store, socket or credential mount is admitted.
    mounts_ok = (len(bm) == len(am) == 1 and bm[0].get("Type") == am[0].get("Type") == "bind"
                 and bm[0].get("Destination") == "/workspace" and am[0].get("Destination") == "/candidate"
                 and bm[0].get("RW") is False and am[0].get("RW") is False)
    return {
        "same_image": before.get("Image") == after.get("Image") == parent["image_identity"] == child["image_identity"],
        "same_unprivileged_user": before["Config"].get("User") == after["Config"].get("User") == "65534:65534",
        "same_environment": sorted(before["Config"].get("Env", [])) == sorted(after["Config"].get("Env", [])),
        "read_projection": mounts_ok and child["projected_files"] == ["solution.py"]
            and "solution.py" in parent["copied_files"]
            and child["source_identity"] == parent["source_identity"],
        "write_surface": bh.get("ReadonlyRootfs") is True and ah.get("ReadonlyRootfs") is True
            and not ah.get("Tmpfs") and not ah.get("VolumesFrom"),
        "network_and_trusted_api": bh.get("NetworkMode") == ah.get("NetworkMode") == "none"
            and not ah.get("PortBindings") and not ah.get("PublishAllPorts") and mounts_ok,
        "capabilities": bh.get("CapDrop") == ah.get("CapDrop") == ["ALL"]
            and not bh.get("CapAdd") and not ah.get("CapAdd")
            and bh.get("Privileged") is False and ah.get("Privileged") is False,
        "no_new_privileges": "no-new-privileges" in bh.get("SecurityOpt", [])
            and "no-new-privileges" in ah.get("SecurityOpt", []),
        "devices_and_namespaces": not bh.get("Devices") and not ah.get("Devices")
            and not ah.get("DeviceRequests") and not ah.get("DeviceCgroupRules")
            and bh.get("PidMode", "") == ah.get("PidMode", "") == ""
            and bh.get("IpcMode") == ah.get("IpcMode") == "private"
            and not ah.get("ExtraHosts") and not ah.get("Links"),
        "resource_limits": all(0 < ah.get(key, 0) <= bh.get(key, 0)
                               for key in ("Memory", "PidsLimit", "NanoCpus")),
    }
