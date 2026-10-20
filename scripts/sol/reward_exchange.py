"""Trusted SSH helper: move bounded JSON data, never execute candidate contents."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

from reward_client import canonical, identity, write_once


def exchange_root(value: str) -> Path:
    path = Path(value).resolve()
    configured = os.environ.get("AUTOSEAL_EXCHANGE_BASE")
    if not configured:
        raise ValueError("Set AUTOSEAL_EXCHANGE_BASE on the trusted remote host")
    if not Path(configured).is_absolute():
        raise ValueError("AUTOSEAL_EXCHANGE_BASE must be absolute")
    allowed = Path(configured).resolve()
    if path.parent != allowed or not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", path.name):
        raise ValueError("exchange must be a named AutoSeal scratch directory")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["pending", "respond"])
    parser.add_argument("--root", type=exchange_root, required=True)
    args = parser.parse_args()
    if args.action == "pending":
        for path in sorted((args.root / "requests").glob("*.json")):
            if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name) or path.is_symlink():
                raise ValueError("invalid exchange request path")
            if (args.root / "responses" / path.name).exists():
                continue
            if path.stat().st_size > 150 * 1024:
                raise ValueError("request exceeded wire budget")
            request = json.loads(path.read_bytes())
            if identity(request) != "sha256:" + path.stem:
                raise ValueError("request content identity mismatch")
            print(json.dumps({"request_id": identity(request), "request": request}, ensure_ascii=False))
            return
        print("null")
    else:
        raw = sys.stdin.buffer.read(150 * 1024 + 1)
        if len(raw) > 150 * 1024:
            raise ValueError("response exceeded wire budget")
        envelope = json.loads(raw)
        response = envelope["response"]
        if identity(response) != envelope["response_id"]:
            raise ValueError("response identity mismatch")
        request_id = response["request_id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", request_id):
            raise ValueError("invalid request identity")
        name = request_id[7:] + ".json"
        request = json.loads((args.root / "requests" / name).read_bytes())
        if identity(request) != request_id or request["bridge_manifest_id"] != response["bridge_manifest_id"]:
            raise ValueError("response is not bound to the pending request")
        write_once(args.root / "responses" / name, canonical(envelope))
        print(json.dumps({"response_id": envelope["response_id"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
