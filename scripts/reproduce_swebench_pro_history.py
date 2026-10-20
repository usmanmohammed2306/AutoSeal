"""Print the pinned, networkless SWE-bench Pro history-leak inspection."""

from __future__ import annotations

import json

from autoseal.swebench_pro_history import reproduce_history_leak


if __name__ == "__main__":
    print(json.dumps(reproduce_history_leak(), indent=2, sort_keys=True))
