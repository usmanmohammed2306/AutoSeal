"""Independent, fixed semantic check for the pinned pytest-dev Verified task.

This script runs inside a fresh copy of the official image. It neither imports
SWE-bench nor reads its grader or native test log. The source patch is applied
before this script starts; candidate-controlled test configuration is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from _pytest.pathlib import visit


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="autoseal-semantic-") as directory:
        root = Path(directory)
        target = root / "target"
        target.mkdir()
        (target / "leaf.txt").write_text("target")
        (root / "link").symlink_to(target, target_is_directory=True)
        blocked = root / "blocked"
        blocked.mkdir()
        (blocked / "leaf.txt").write_text("blocked")
        observed = {str(Path(entry.path).relative_to(root))
                    for entry in visit(str(root), lambda entry: entry.name != "blocked")}
    checks = {
        "symlink_directory_descended": "link/leaf.txt" in observed,
        "regular_directory_descended": "target/leaf.txt" in observed,
        "recurse_predicate_respected": "blocked/leaf.txt" not in observed,
    }
    print(json.dumps({"schema_version": 1, "checks": checks, "observed": sorted(observed)}, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
