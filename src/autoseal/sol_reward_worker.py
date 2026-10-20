"""A Mac-side reward worker, relaying only bounded JSON over existing Sol SSH."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shlex
import subprocess

from autoseal.reward_bridge import DockerRewardWorker
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


class SolRewardRelay:
    def __init__(self, store: ContentAddressedStore, manifest_id: str, exchange_name: str):
        import re
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", exchange_name):
            raise ValueError("invalid exchange name")
        self.store = store
        self.worker = DockerRewardWorker(store, manifest_id)
        configuration = store.get_json(self.worker.manifest.experiment_id)
        root = Path(__file__).resolve().parents[2]
        for relative, expected in configuration["code_identities"].items():
            observed = "sha256:" + hashlib.sha256((root / relative).read_bytes()).hexdigest()
            if observed != expected:
                raise IntegrityError("reward driver changed after experiment freeze")
        required = ("AUTOSEAL_SOL_HOST", "AUTOSEAL_SOL_CONTROL", "AUTOSEAL_REMOTE_HELPER",
                    "AUTOSEAL_REMOTE_PYTHON", "AUTOSEAL_EXCHANGE_BASE")
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError("Set reward-relay configuration: " + ", ".join(missing))
        self.host = os.environ["AUTOSEAL_SOL_HOST"]
        if self.host.startswith("-") or not re.fullmatch(r"[a-zA-Z0-9_.@-]+", self.host):
            raise ValueError("invalid Sol SSH host")
        self.control = os.environ["AUTOSEAL_SOL_CONTROL"]
        self.helper = os.environ["AUTOSEAL_REMOTE_HELPER"]
        self.python = os.environ["AUTOSEAL_REMOTE_PYTHON"]
        self.exchange_base = os.environ["AUTOSEAL_EXCHANGE_BASE"]
        if not Path(self.exchange_base).is_absolute():
            raise ValueError("AUTOSEAL_EXCHANGE_BASE must be absolute")
        self.remote_root = str(Path(self.exchange_base) / exchange_name)

    def _exchange(self, action: str, payload=None):
        command = shlex.join(["env", "AUTOSEAL_EXCHANGE_BASE=" + self.exchange_base,
                              self.python, self.helper, action, "--root", self.remote_root])
        process = subprocess.run(["ssh", "-S", self.control, "-o", "BatchMode=yes", self.host, command],
                                 input=None if payload is None else canonical_json(payload),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if process.returncode:
            raise RuntimeError("Sol reward transport failed: " + process.stderr.decode(errors="replace")[:500])
        if len(process.stdout) > 150 * 1024:
            raise ValueError("remote reward response exceeds wire budget")
        return json.loads(process.stdout)

    def process_one(self):
        pending = self._exchange("pending")
        if pending is None:
            return None
        request_id = self.store.put_json(pending["request"])
        if request_id != pending["request_id"]:
            raise IntegrityError("remote request identity mismatch")
        response_id = self.worker.evaluate(request_id)
        response = self.store.get_json(response_id)
        acknowledgement = self._exchange("respond", {"response_id": response_id, "response": response})
        if acknowledgement != {"response_id": response_id}:
            raise IntegrityError("remote response acknowledgement mismatch")
        return {"request_id": request_id, "response_id": response_id, "status": response["status"]}
