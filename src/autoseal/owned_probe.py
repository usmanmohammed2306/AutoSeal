"""Active checks of the exact owned-verifier Docker execution profile.

The probe never imports candidate code. It shares the evaluator's creation and
cleanup path and binds its receipts to one immutable revision and candidate.
It is finite capability evidence, not proof of kernel escape resistance.
"""

from __future__ import annotations

import json
from pathlib import Path
import uuid

from autoseal.managed_receipts import verify_owned_transport
from autoseal.owned_verifier import execute_owned_payload
from autoseal.result_binding import ResultContext
from autoseal.storage import ContentAddressedStore, IntegrityError


PROBE_CODE = """
import errno, json, os, socket, sys
from pathlib import Path
payload = json.loads(sys.argv[1])
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
def write_denied(path):
    try:
        with open(path, 'wb') as target:
            target.write(b'probe')
        return False
    except OSError as exc:
        return exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
def denied_network(family, address):
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        sock.connect(address)
        return False
    except OSError as exc:
        return exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL)
    finally:
        if sock is not None:
            sock.close()
def cgroup(name):
    path = Path('/sys/fs/cgroup') / name
    return path.read_text().strip() if path.is_file() else None
print(json.dumps({
    'nonce': payload['nonce'],
    'uid': os.getuid(), 'euid': os.geteuid(),
    'root_write_denied': write_denied('/autoseal-owned-probe'),
    'candidate_write_denied': write_denied('/candidate/.autoseal-owned-probe'),
    'projected_entries': sorted(path.name for path in Path('/candidate').iterdir()),
    'docker_socket_absent': not Path('/var/run/docker.sock').exists(),
    'named_credentials_absent': not any(key in os.environ for key in (
        'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'HF_TOKEN', 'VLLM_API_KEY', 'AUTOSEAL_DATABASE_URL')),
    'effective_capabilities': int(status['CapEff'].strip(), 16),
    'no_new_privileges': status['NoNewPrivs'].strip(),
    'seccomp': status['Seccomp'].strip(),
    'ipv4_route_denied': denied_network(socket.AF_INET, ('192.0.2.1', 9)),
    'ipv6_route_denied': denied_network(socket.AF_INET6, ('2001:db8::1', 9, 0, 0)),
    'memory_limit': cgroup('memory.max'), 'pid_limit': cgroup('pids.max'),
    'cpu_limit': cgroup('cpu.max'), 'swap_limit': cgroup('memory.swap.max'),
}, allow_nan=False))
"""


def interpret_probe(process: dict, nonce: str, *, projected_entries=("solution.py",)) -> dict:
    expected = {"nonce": nonce, "uid": 65534, "euid": 65534,
        "root_write_denied": True, "candidate_write_denied": True,
        "projected_entries": list(projected_entries), "docker_socket_absent": True,
        "named_credentials_absent": True, "effective_capabilities": 0,
        "no_new_privileges": "1", "seccomp": "2", "ipv4_route_denied": True,
        "ipv6_route_denied": True, "memory_limit": "536870912", "pid_limit": "128",
        "cpu_limit": "100000 100000", "swap_limit": "0"}
    observed = None
    if (process["status"] == "exited_zero" and not process["stdout_truncated"]
            and not process["stderr_truncated"]):
        try:
            value = json.loads(process["stdout"])
            if isinstance(value, dict):
                observed = value
        except (ValueError, TypeError):
            pass
    gates = {key: observed is not None and key in observed and type(observed[key]) is type(value)
             and observed[key] == value for key, value in expected.items()}
    return {"observed": observed, "gates": gates, "passed": all(gates.values())}


def execute_owned_probe(store: ContentAddressedStore, candidate: Path, name: str,
                         *, image: str, context: ResultContext) -> str:
    payload = {"nonce": uuid.uuid4().hex}
    execution = execute_owned_payload(candidate, name, store, image=image, worker=PROBE_CODE, payload=payload)
    if execution["candidate_identity"] != context.candidate:
        raise IntegrityError("probe candidate differs from its frozen context")
    result = {"schema_version": 1, "kind": "owned_profile_probe", "execution": execution,
        "context": context.model_dump(mode="json"), "context_identity": context.identity,
        **interpret_probe(execution["process"], payload["nonce"]),
        "limitations": ["One IPv4 and one IPv6 test destination, not exhaustive network coverage.",
            "Credential checks cover named environment keys and the known Docker socket only.",
            "Cgroup values are observed; no OOM, PID exhaustion or throughput benchmark is attempted.",
            "No kernel escape or public hostile-code security guarantee."]}
    return store.put_json(result)


def verify_owned_probe(store: ContentAddressedStore, identity: str, snapshot: dict,
                        *, image: str, context: ResultContext) -> dict:
    result = store.get_json(identity)
    if (result["schema_version"] != 1 or result["kind"] != "owned_profile_probe"
            or ResultContext.model_validate(result["context"]) != context
            or result["context_identity"] != context.identity):
        raise IntegrityError("probe belongs to another revision or context")
    execution = result["execution"]
    payload = store.get_json(execution["inputs_identity"])
    if set(payload) != {"nonce"} or not isinstance(payload["nonce"], str) or len(payload["nonce"]) != 32:
        raise IntegrityError("invalid probe challenge")
    process = verify_owned_transport(store, execution, snapshot, image=image, worker=PROBE_CODE, payload=payload)
    checked = interpret_probe(process, payload["nonce"])
    if any(result[key] != checked[key] for key in ("observed", "gates", "passed")):
        raise IntegrityError("probe summary contradicts retained runtime output")
    return result
