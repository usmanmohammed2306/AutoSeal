"""Active, scoped probes of the selected Mac Docker research environment."""

import json

from autoseal.environment import DockerAgentEnvironment, ToolAction
from autoseal.execution import CommandStatus
from autoseal.storage import ContentAddressedStore


PROBE_CODE = """
import errno, json, os, socket
from pathlib import Path
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
try:
    Path('/autoseal_probe').write_text('probe')
    root_read_only = False
except OSError as error:
    root_read_only = error.errno == errno.EROFS
Path('/workspace/.autoseal-probe').write_text('probe')
workspace_writable = Path('/workspace/.autoseal-probe').read_text() == 'probe'
Path('/workspace/.autoseal-probe').unlink()
sock = socket.socket()
sock.settimeout(0.2)
try:
    sock.connect(('192.0.2.1', 9))
    outbound_probe_denied = False
except OSError:
    outbound_probe_denied = True
finally:
    sock.close()
def cgroup(name):
    path = Path('/sys/fs/cgroup') / name
    return path.read_text().strip() if path.is_file() else None
print(json.dumps({
    'root_read_only': root_read_only,
    'workspace_writable': workspace_writable,
    'docker_socket_absent': not Path('/var/run/docker.sock').exists(),
    'known_credentials_absent': not any(name in os.environ for name in ('VLLM_API_KEY', 'HF_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'AUTOSEAL_TOKEN_FILE')),
    'capabilities_dropped': int(status['CapEff'].strip(), 16) == 0,
    'no_new_privileges': status['NoNewPrivs'].strip() == '1',
    'outbound_probe_denied': outbound_probe_denied,
    'memory_limit': cgroup('memory.max'),
    'pid_limit': cgroup('pids.max'),
    'cpu_limit': cgroup('cpu.max'),
}))
"""


def probe_docker_provider(store: ContentAddressedStore) -> dict:
    environment = DockerAgentEnvironment()
    try:
        handle = environment.reset()
        observation = environment.step(ToolAction(kind="command", command=["python", "-c", PROBE_CODE]))
        evidence = store.put_json(observation.process.to_dict())
        if observation.process.status is not CommandStatus.EXITED_ZERO:
            return {"scope": "Mac Docker research probe", "passed": False,
                    "process_evidence_id": evidence, "reason": "probe process did not complete"}
        observed = json.loads(observation.process.stdout)
        required = ("root_read_only", "workspace_writable", "docker_socket_absent", "known_credentials_absent",
                    "capabilities_dropped", "no_new_privileges", "outbound_probe_denied")
        gates = {name: observed[name] is True for name in required}
        gates.update({"memory_limit": observed["memory_limit"] == "536870912",
                      "pid_limit": observed["pid_limit"] == "128",
                      "cpu_limit": observed["cpu_limit"] == "100000 100000"})
        environment.freeze()
        return {"scope": "Mac Docker research probe, not a universal hostile-code guarantee",
                "passed": all(gates.values()), "gates": gates, "observed": observed,
                "image_identity": handle.image_identity, "process_evidence_id": evidence,
                "probe_code_id": store.put_bytes(PROBE_CODE.encode()),
                "limitations": ["One outbound target, not a proof over every network path.",
                                "Credential absence checks named environment keys and the Docker socket, not every possible secret.",
                                "No disk quota or kernel escape resistance is proved by this probe.",
                                "Verifier ownership, result binding, and artifact rollback require separate evidence."]}
    finally:
        environment.terminate()
