"""Defensive security helpers: headers, rate limiting, output sanitization."""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# --- Limits ---
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 5 * 1024 * 1024
MAX_TIMELINE_EVENTS = 200
MAX_SUMMARY_CHARS = 4_000
MAX_EVENT_FIELD_CHARS = 2_000
MAX_TITLE_CHARS = 200
MAX_IP_CHARS = 64
MAX_TIMESTAMP_CHARS = 64
MAX_PROVIDER_CHARS = 80

SEVERITIES = frozenset({"Info", "Warning", "Critical"})
RISKS = frozenset({"Low", "Medium", "High", "Critical"})

# Rate limit: requests per window for mutating/analyze endpoints
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_REQUESTS = 30
RATE_LIMITED_PREFIXES = ("/api/analyze",)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach baseline OWASP-oriented HTTP response headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Allow self + Tailwind CDN + Google Fonts used by the UI.
        response.headers.setdefault(
            "Content-Security-Policy",
            "; ".join(
                [
                    "default-src 'self'",
                    "base-uri 'self'",
                    "object-src 'none'",
                    "frame-ancestors 'none'",
                    "form-action 'self'",
                    "img-src 'self' data:",
                    "font-src 'self' https://fonts.gstatic.com",
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com",
                    "script-src 'self' https://cdn.tailwindcss.com",
                    "connect-src 'self'",
                ]
            ),
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory per-IP rate limiter for analysis endpoints."""

    def __init__(self, app, max_requests: int = RATE_LIMIT_MAX_REQUESTS, window_sec: int = RATE_LIMIT_WINDOW_SEC):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_sec = window_sec
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _client_ip(self, request: Request) -> str:
        # Prefer direct peer address; ignore spoofable X-Forwarded-For for local demo.
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    def _allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            cutoff = now - self.window_sec
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if request.method.upper() == "POST" and path.startswith(RATE_LIMITED_PREFIXES):
            ip = self._client_ip(request)
            if not self._allowed(f"{ip}:{path}"):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many analysis requests. Please wait and try again."},
                    headers={"Retry-After": str(self.window_sec)},
                )
        return await call_next(request)


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: object, max_chars: int) -> str:
    """Strip control chars and truncate untrusted LLM/user-derived strings."""
    text = _CTRL_RE.sub("", str(value if value is not None else ""))
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def sanitize_severity(value: object) -> str:
    sev = str(value or "Info").strip().title()
    return sev if sev in SEVERITIES else "Warning"


def sanitize_risk(value: object) -> str:
    risk = str(value or "Low").strip().title()
    return risk if risk in RISKS else "Medium"


def safe_css_token(value: str, allowed: frozenset[str], fallback: str) -> str:
    return value if value in allowed else fallback


def is_probably_text_upload(content_type: str | None, filename: str) -> bool:
    """Reject clearly non-text uploads while allowing browsers that omit content-type."""
    if not content_type:
        return True
    ct = content_type.split(";")[0].strip().lower()
    if ct in {"application/octet-stream", "binary/octet-stream"}:
        return True
    if ct.startswith("text/"):
        return True
    if ct in {"application/json", "application/csv", "text/csv"}:
        return True
    # Some browsers send empty or weird types for .log — still allow by extension.
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return suffix in {"log", "txt", "csv"}
