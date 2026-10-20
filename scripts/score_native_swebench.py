"""Print an integrity-checked scorecard for the archived native case."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from autoseal.native_scorecard import score_native_archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Directory containing index.json and audit_index.json")
    args = parser.parse_args()
    print(json.dumps(score_native_archive(args.archive), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
