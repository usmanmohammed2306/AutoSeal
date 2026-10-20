"""Create a private, reusable service credential without printing it."""

import argparse
import os
from pathlib import Path
import secrets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    arguments = parser.parse_args()
    arguments.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(arguments.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(secrets.token_urlsafe(48))
    print("Created private inference credential. Value is not displayed.")


if __name__ == "__main__":
    main()
