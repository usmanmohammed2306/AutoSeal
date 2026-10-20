"""Authenticate every server route, not only vLLM's /v1 endpoints."""

import hmac
import os

from starlette.responses import JSONResponse


async def require_token(request, call_next):
    token = os.environ.get("VLLM_API_KEY", "")
    supplied = request.headers.get("authorization", "")
    if not token or not hmac.compare_digest(supplied, "Bearer " + token):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return await call_next(request)
