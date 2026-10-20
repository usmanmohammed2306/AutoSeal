"""Export a scripted reward preflight with its complete local CAS closure."""

import argparse
import json
from pathlib import Path

from autoseal.reward_population import (
    export_controlled_reward_population, verify_controlled_reward_population_archive,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    index = export_controlled_reward_population(args.store, report, args.destination)
    assert verify_controlled_reward_population_archive(args.destination) == index
    print(json.dumps(index, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
