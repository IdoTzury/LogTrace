"""Log preprocessing: noise filtering and chunking for LLM context limits."""

from __future__ import annotations

import re

# Soft limit so chunks stay within typical model context windows
DEFAULT_MAX_CHARS = 48_000
DEFAULT_MAX_LINES = 800


def clean_log_text(raw: str) -> str:
    """Strip empty lines and excessive whitespace while preserving log content."""
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines)


def count_non_empty_lines(raw: str) -> int:
    return sum(1 for line in raw.splitlines() if line.strip())


def chunk_log(
    text: str,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_lines: int = DEFAULT_MAX_LINES,
) -> list[str]:
    """Split cleaned logs into overlapping-safe chunks by line count / char budget."""
    lines = text.splitlines()
    if not lines:
        return []

    chunks: list[str] = []
    current: list[str] = []
    current_chars = 0

    for line in lines:
        line_len = len(line) + 1
        would_exceed = (
            current
            and (
                len(current) >= max_lines
                or current_chars + line_len > max_chars
            )
        )
        if would_exceed:
            chunks.append("\n".join(current))
            current = []
            current_chars = 0
        current.append(line)
        current_chars += line_len

    if current:
        chunks.append("\n".join(current))

    return chunks


# Patterns used by the heuristic fallback analyzer
_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"(failed password|authentication failure|invalid user)", re.I),
        "Critical",
        "Failed authentication / brute-force indicator",
        "Multiple or failed login attempts often precede account takeover.",
    ),
    (
        re.compile(r"(union\s+select|or\s+1\s*=\s*1|drop\s+table|'--|;--)", re.I),
        "Critical",
        "SQL injection attempt",
        "Query payload matches common SQL injection patterns targeting backend databases.",
    ),
    (
        re.compile(r"(<script|javascript:|onerror\s*=|document\.cookie)", re.I),
        "Critical",
        "Cross-site scripting (XSS) attempt",
        "Request contains script/event-handler payloads typical of XSS probes.",
    ),
    (
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)", re.I),
        "Critical",
        "Path traversal / sensitive file access",
        "Directory traversal or direct access attempt against sensitive system files.",
    ),
    (
        re.compile(r"(/\.(env|git)|backup\.sql|secrets\.ya?ml|wp-admin|/admin)", re.I),
        "Warning",
        "Sensitive path or admin endpoint probe",
        "Requester probed admin panels or configuration/secret files.",
    ),
    (
        re.compile(r"(wget|curl).*(http|ftp)", re.I),
        "Critical",
        "Suspicious remote download",
        "Host executed a network fetch that may stage malware or a second-stage payload.",
    ),
    (
        re.compile(r"(chmod\s+\+x|/tmp/\.|base64\s+-d)", re.I),
        "Critical",
        "Suspicious command execution",
        "Command pattern suggests payload staging or privilege abuse.",
    ),
    (
        re.compile(r"accepted password for root", re.I),
        "Critical",
        "Successful root login after failures",
        "Root authentication succeeded — high-value compromise indicator if unexpected.",
    ),
]


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TS_RE = re.compile(
    r"("
    r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}"  # Apache
    r"|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"  # syslog
    r"|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"  # ISO
    r")"
)


def heuristic_analyze(cleaned: str, lines_analyzed: int) -> dict:
    """Rule-based DFIR timeline when no LLM API key is configured."""
    events: list[dict] = []
    seen_titles: set[str] = set()

    for line in cleaned.splitlines():
        for pattern, severity, title, explanation in _PATTERNS:
            if not pattern.search(line):
                continue
            ip_match = _IP_RE.search(line)
            ts_match = _TS_RE.search(line)
            key = f"{title}|{ip_match.group(0) if ip_match else ''}|{ts_match.group(0) if ts_match else line[:40]}"
            if key in seen_titles:
                continue
            seen_titles.add(key)
            events.append(
                {
                    "timestamp": ts_match.group(0) if ts_match else "N/A",
                    "severity": severity,
                    "source_ip": ip_match.group(0) if ip_match else "N/A",
                    "event_title": title,
                    "description": f"{explanation} Evidence: {line[:220]}",
                }
            )
            break

    critical = sum(1 for e in events if e["severity"] == "Critical")
    warning = sum(1 for e in events if e["severity"] == "Warning")

    if critical >= 5:
        risk = "Critical"
    elif critical >= 2:
        risk = "High"
    elif critical >= 1 or warning >= 3:
        risk = "Medium"
    elif events:
        risk = "Low"
    else:
        risk = "Low"

    if events:
        summary = (
            f"Heuristic DFIR scan of {lines_analyzed} log lines found "
            f"{len(events)} suspicious events ({critical} critical, {warning} warning). "
            "Primary concerns include authentication abuse, injection probes, "
            "and/or sensitive-path reconnaissance."
        )
    else:
        summary = (
            f"Heuristic DFIR scan of {lines_analyzed} log lines found no strong IoCs. "
            "Activity appears mostly benign or outside known attack signatures."
        )

    return {
        "summary": summary,
        "overall_risk": risk,
        "timeline": events,
        "lines_analyzed": lines_analyzed,
        "suspicious_events": len(events),
        "provider_used": "heuristic",
    }
