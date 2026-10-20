"""Print one pinned SWE-bench Pro workspace-preservation experiment as JSON."""

import json

from autoseal.swebench_pro_history import reproduce_workspace_projection


def main() -> None:
    print(json.dumps(reproduce_workspace_projection(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
