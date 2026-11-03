# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""ASGI middleware enforcing a request body size limit and adding security headers."""

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
_SECURITY_HEADERS = (
    (b"content-security-policy", _CONTENT_SECURITY_POLICY.encode("ascii")),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
)


class _BodyTooLargeError(Exception):
    """Raised by the wrapped receive callable once the byte budget is exceeded."""


class BodySizeLimitMiddleware:
    """Rejects requests whose body exceeds ``max_bytes`` with HTTP 413.

    The Content-Length header is checked first (fast path); the bytes actually received are counted as well, for
    chunked bodies without a Content-Length header.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        """Wrap ``app`` and reject bodies larger than ``max_bytes``."""
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle one ASGI connection."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = dict(scope.get("headers", [])).get(b"content-length")
        if content_length is not None and content_length.isdigit() and int(content_length) > self.max_bytes:
            await self._reject(send)
            return

        total = 0
        exceeded = False

        async def limited_receive() -> Message:
            nonlocal total, exceeded
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLargeError
            return message

        async def guarded_send(message: Message) -> None:
            # inner error handlers answer the aborted request with a 500; the 413 below replaces it
            if not exceeded:
                await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"request body too large"})


class SecurityHeadersMiddleware:
    """Adds restrictive browser security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap ``app``."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle one ASGI connection."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *_SECURITY_HEADERS]
            await send(message)

        await self.app(scope, receive, send_with_headers)
