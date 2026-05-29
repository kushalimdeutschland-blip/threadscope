"""
Security middleware — headers, body size limits, request logging.
"""

from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from config import Settings

logger = logging.getLogger("threatscope.access")

CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in {"POST", "PUT", "PATCH"}:
            content_length = request.headers.get("content-length")
            if content_length:
                limit = (
                    self.settings.max_upload_bytes
                    if request.url.path == "/api/analyze-file"
                    else self.settings.max_body_bytes
                )
                if int(content_length) > limit:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)

        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-XSS-Protection"] = "0"  # deprecated; CSP is the control
        if "server" in response.headers:
            del response.headers["server"]

        if self.settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        client = request.client.host if request.client else "-"
        logger.info(
            "%s %s %s %d %.1fms",
            client,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response
