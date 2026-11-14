"""One narrow, read-only Docker profile for candidate-facing execution."""

import json
from pathlib import Path
from typing import Optional


def readonly_python_command(name: str, root: Path, image: str, worker: str, payload,
                             *, scope: Optional[str] = None) -> list[str]:
    labels = ["--label", "autoseal.scope=" + scope] if scope else []
    return ["docker", "create", "--name", name, *labels, "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--pids-limit", "128", "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
        "--mount", f"type=bind,src={root},dst=/candidate,readonly",
        "--entrypoint", "python", image, "-I", "-c", worker, json.dumps(payload)]
