"""Check a trusted Sol training environment without loading a model or candidate code.

This is a hardware and package pilot only. It is not SFT, GRPO, or a research
result. It intentionally never executes agent-generated artifacts on Sol.
"""

from __future__ import annotations

import importlib.metadata
import json
import platform
import sys


REQUIRED_PACKAGES = ("torch", "transformers", "trl", "peft", "datasets")


def inspect() -> dict:
    packages: dict[str, str | None] = {}
    for package in REQUIRED_PACKAGES:
        try:
            packages[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            packages[package] = None

    report = {
        "schema_version": 1,
        "purpose": "trusted_training_environment_preflight",
        "python": sys.version.split()[0],
        "machine": platform.machine(),
        "packages": packages,
        "cuda_available": False,
        "gpu_name": None,
        "matrix_multiply_ok": False,
    }
    if packages["torch"] is None:
        return report

    import torch

    report["cuda_available"] = torch.cuda.is_available()
    if not torch.cuda.is_available():
        return report
    report["gpu_name"] = torch.cuda.get_device_name(0)
    left = torch.eye(32, device="cuda")
    right = torch.ones((32, 32), device="cuda")
    observed = left @ right
    torch.cuda.synchronize()
    report["matrix_multiply_ok"] = bool(torch.equal(observed, right))
    return report


def main() -> int:
    report = inspect()
    print(json.dumps(report, sort_keys=True))
    return 0 if (
        all(report["packages"].values())
        and report["cuda_available"]
        and report["matrix_multiply_ok"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
