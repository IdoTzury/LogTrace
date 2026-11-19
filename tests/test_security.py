"""Defensive security tests — assert hardened behavior, not attack recipes."""

from __future__ import annotations

import os

os.environ["AI_PROVIDER"] = "heuristic"

from fastapi.testclient import TestClient

from backend.agent import _normalize_result
from backend.main import app
from backend.security import (
    MAX_TEXT_CHARS,
    sanitize_risk,
    sanitize_severity,
    sanitize_text,
)

client = TestClient(app)


def test_security_headers_present():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")
    assert res.headers.get("Referrer-Policy") == "no-referrer"


def test_sample_name_allowlist_rejects_unknown():
    res = client.get("/api/sample", params={"name": "../etc/passwd"})
    assert res.status_code == 404
    res_ok = client.get("/api/sample", params={"name": "apache"})
    assert res_ok.status_code == 200
    assert "HTTP" in res_ok.json()["content"] or "GET" in res_ok.json()["content"]


def test_reject_unsupported_extension():
    res = client.post(
        "/api/analyze/file",
        files={"file": ("malware.exe", b"MZ fake", "application/octet-stream")},
    )
    assert res.status_code == 400
    assert "Unsupported file type" in res.json()["detail"]


def test_reject_binary_nul_in_log_upload():
    res = client.post(
        "/api/analyze/file",
        files={"file": ("evil.log", b"ok line\n\x00\x00secret", "text/plain")},
    )
    assert res.status_code == 400
    assert "Binary" in res.json()["detail"]


def test_reject_pathful_filename_uses_suffix_only():
    # Path components are stripped; .log suffix still accepted for content.
    res = client.post(
        "/api/analyze/file",
        files={"file": ("../../tmp/escape.log", b"Nov 15 07:00:01 host sshd: hello\n", "text/plain")},
    )
    assert res.status_code == 200
    assert res.json()["provider_used"] == "heuristic"


def test_text_body_max_length_enforced():
    oversized = "A" * (MAX_TEXT_CHARS + 10)
    res = client.post("/api/analyze/text", json={"text": oversized})
    assert res.status_code == 422


def test_analyze_valid_text_still_works():
    res = client.post(
        "/api/analyze/text",
        json={"text": "Nov 15 07:15:22 server sshd: Failed password for root from 1.2.3.4 port 22 ssh2"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["overall_risk"] in {"Low", "Medium", "High", "Critical"}
    assert isinstance(body["timeline"], list)


def test_sanitize_severity_and_risk_whitelist():
    assert sanitize_severity('Critical"><img src=x>') == "Warning"
    assert sanitize_severity("critical") == "Critical"
    assert sanitize_risk("High; drop table") == "Medium"
    assert sanitize_risk("low") == "Low"


def test_normalize_strips_html_like_llm_fields():
    dirty = {
        "summary": "ok\x00summary<script>",
        "overall_risk": 'Critical"><svg/onload=1>',
        "timeline": [
            {
                "timestamp": "t1",
                "severity": 'Warning"><img src=x onerror=alert(1)>',
                "source_ip": "10.0.0.1",
                "event_title": "<b>title</b>",
                "description": "desc\x01more",
            }
        ],
    }
    clean = _normalize_result(dirty, 3, "test")
    assert clean["overall_risk"] == "Medium"
    assert clean["timeline"][0]["severity"] == "Warning"
    assert "<" in clean["timeline"][0]["event_title"]  # text preserved, not interpreted
    assert "\x00" not in clean["summary"]
    assert "\x01" not in clean["timeline"][0]["description"]


def test_sanitize_text_truncates():
    assert len(sanitize_text("x" * 500, 50)) <= 50


def test_rate_limit_analyze_endpoints():
    limited = TestClient(app)
    payload = {"text": "GET /index.html 200"}
    codes = []
    for _ in range(35):
        codes.append(limited.post("/api/analyze/text", json=payload).status_code)
    assert 429 in codes
    assert codes.count(200) + codes.count(429) == 35
