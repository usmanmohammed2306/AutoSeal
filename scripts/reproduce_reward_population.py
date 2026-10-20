"""Run the frozen three-candidate reward-discrimination preflight on Mac Docker."""

import argparse
import json
from pathlib import Path

from autoseal.reward_population import run_controlled_reward_population


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True,
                        help="Local content-addressed evidence directory")
    parser.add_argument("--output", type=Path,
                        help="Optional new JSON report path; existing files are never replaced")
    args = parser.parse_args()
    if args.output is not None and args.output.exists():
        raise FileExistsError("refusing to replace a reward-population report")
    rendered = json.dumps(run_controlled_reward_population(args.store), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
