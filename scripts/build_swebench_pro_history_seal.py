"""Build and validate a pinned, history-free SWE-bench Pro task image."""

import json

from autoseal.swebench_pro_history import build_and_check_sealed_image


def main() -> None:
    print(json.dumps(build_and_check_sealed_image(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
