"""Allow AutoSeal to run through ``python -m autoseal``."""

from autoseal.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
