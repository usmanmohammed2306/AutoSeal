"""Small single-operator access policy for API, artifacts and event streams."""

from __future__ import annotations

import hmac
import json


class AccessPolicy:
    def __init__(self, app, *, operator_token=None, reader_token=None, max_body_bytes=65536):
        self.app = app
        self.operator_token, self.reader_token = operator_token, reader_token
        if reader_token and not operator_token:
            raise ValueError("reader access requires an operator token")
        for token in (operator_token, reader_token):
            if token is not None and (len(token) < 32 or not token.isascii() or any(c.isspace() for c in token)):
                raise ValueError("access tokens require at least 32 non-whitespace ASCII characters")
        if operator_token and reader_token and hmac.compare_digest(operator_token, reader_token):
            raise ValueError("operator and reader tokens must differ")
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def reject(status, message):
            body = json.dumps({"detail": message}).encode()
            headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]
            if status == 401:
                headers.append((b"www-authenticate", b"Bearer"))
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": body})

        if self.operator_token and scope["path"] != "/api/health":
            values = [v for k, v in scope["headers"] if k.lower() == b"authorization"]
            supplied = values[0].decode("ascii", errors="replace") if len(values) == 1 else ""
            if not supplied.isascii():
                supplied = ""
            operator = hmac.compare_digest(supplied, "Bearer " + self.operator_token)
            reader = bool(self.reader_token) and hmac.compare_digest(supplied, "Bearer " + self.reader_token)
            if not (operator or reader):
                return await reject(401, "authentication required")
            # Legacy research GET handlers can execute experiments. Saved evidence
            # is readable; launching an experiment requires the operator.
            path = scope["path"]
            saved = (path.startswith("/api/runs") or path.startswith("/api/workflows")
                     or path in {"/api/cases", "/api/access", "/api/research/managed-repair", "/api/research/terminal-shell", "/api/research/sft-calibration"}
                     or path.startswith("/api/research/native-swebench")
                     or path.startswith("/api/research/training-pilots"))
            if not operator and (scope["method"] not in {"GET", "HEAD"} or not saved):
                return await reject(403, "operator access required")
            scope["autoseal.role"] = "operator" if operator else "reader"
        else:
            scope["autoseal.role"] = "local" if not self.operator_token else "anonymous"

        # Bound streamed bytes too, including chunked requests without a length.
        # Reject before any mutation handler receives a byte.
        messages, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            messages.append(message)
            size += len(message.get("body", b""))
            if size > self.max_body_bytes:
                return await reject(413, "request body exceeds the byte budget")
            if not message.get("more_body", False):
                break
        async def bounded_receive():
            if messages:
                return messages.pop(0)
            return await receive()
        await self.app(scope, bounded_receive, send)
