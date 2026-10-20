"""Build and inspect four restricted SWE-bench Pro semantic-audit controls."""

import json

from autoseal.swebench_pro_history import (
    build_semantic_audit_images, check_semantic_audit_matrix,
)


def main() -> None:
    build_semantic_audit_images()
    print(json.dumps(check_semantic_audit_matrix(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
