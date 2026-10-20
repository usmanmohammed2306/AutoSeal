import asyncio
import importlib.util
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts/sol/autoseal_server_auth.py"
SPEC = importlib.util.spec_from_file_location("autoseal_server_auth", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("path", ["/health", "/v1/models", "/metrics", "/version"])
def test_server_auth_protects_non_v1_routes(monkeypatch, path):
    monkeypatch.setenv("VLLM_API_KEY", "private-test-key")
    async def next_handler(request):
        return JSONResponse({"ok": True})
    def request(headers):
        return Request({"type": "http", "path": path, "headers": headers})
    rejected = asyncio.run(MODULE.require_token(request([]), next_handler))
    assert rejected.status_code == 401
    accepted = asyncio.run(MODULE.require_token(request([(b"authorization", b"Bearer private-test-key")]), next_handler))
    assert accepted.status_code == 200
