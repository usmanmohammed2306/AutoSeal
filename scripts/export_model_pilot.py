"""Export only the verified CAS object graphs named by a pilot index."""

import argparse
import json
from pathlib import Path

from autoseal.model_run import export_model_run
from autoseal.storage import ContentAddressedStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    index = json.loads(arguments.index.read_text())
    source = ContentAddressedStore(arguments.source)
    destination = ContentAddressedStore(arguments.destination)
    for case in index["cases"]:
        export_model_run(source, case["identity"], destination)
    print(f"Verified and exported {len(index['cases'])} recorded model runs.")


if __name__ == "__main__":
    main()
