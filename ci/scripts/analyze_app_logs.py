#!/usr/bin/env python3
"""Analyze Spring Boot container logs for suspicious runtime patterns during ZAP."""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SQL_PATTERNS = (
    re.compile(r"sql syntax", re.I),
    re.compile(r"syntax error", re.I),
    re.compile(r"ORA-\d+", re.I),
    re.compile(r"mysql error", re.I),
    re.compile(r"SQLState", re.I),
    re.compile(r"bad SQL grammar", re.I),
)

PATH_TRAVERSAL_PATTERNS = (
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/"),
    re.compile(r"/proc/"),
)

STACK_TRACE_PATTERNS = (
    re.compile(r"\bat com\.sun\b", re.I),
    re.compile(r"\bat java\.", re.I),
    re.compile(r"NullPointerException", re.I),
    re.compile(r"StackOverflowError", re.I),
)

HTTP_PATH_RE = re.compile(
    r'(?:"|\b)(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"?]+)|'
    r'(?:^|\s)(/[^\s"]+)\s+(?:401|403|200)\b|'
    r'(?:^|\s)(/[^\s"]+)\?[^\s"]*',
    re.I,
)
STATUS_RE = re.compile(r"\b(401|403|200)\b")
TIME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def extract_time(line: str) -> str:
    match = TIME_RE.match(line.strip())
    if match:
        return match.group(1)
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def extract_path(line: str) -> str | None:
    for match in HTTP_PATH_RE.finditer(line):
        path = match.group(1) or match.group(2)
        if path and path.startswith("/"):
            return path.split("?")[0]
    uri_match = re.search(r'uri=([^\s,]+)|path=([^\s,]+)', line, re.I)
    if uri_match:
        return (uri_match.group(1) or uri_match.group(2)).split("?")[0]
    return None


def make_alert(rule: str, output: str, time: str, priority: str = "WARNING") -> dict:
    return {
        "time": time,
        "priority": priority,
        "rule": rule,
        "output": output[:500],
    }


def analyze_logs(lines: list[str]) -> list[dict]:
    alerts: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, output: str, time: str) -> None:
        key = (rule, output[:200])
        if key in seen:
            return
        seen.add(key)
        alerts.append(make_alert(rule, output, time))

    error_count = 0
    denied_paths: dict[str, str] = {}

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        time_val = extract_time(stripped)

        for pattern in SQL_PATTERNS:
            if pattern.search(stripped):
                add("SQL Error Detected", stripped, time_val)
                break

        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern.search(stripped):
                add("Path Traversal Attempt", stripped, time_val)
                break

        for pattern in STACK_TRACE_PATTERNS:
            if pattern.search(stripped):
                add("Stack Trace Detected", stripped, time_val)
                break

        if re.search(r"\bException\b", stripped) or re.search(r"\bERROR\b", stripped):
            error_count += 1

        status_match = STATUS_RE.search(stripped)
        path = extract_path(stripped)
        if status_match and path:
            status = status_match.group(1)
            if status in ("401", "403"):
                denied_paths[path] = time_val
            elif status == "200" and path in denied_paths:
                add(
                    "Auth Bypass Attempt",
                    f"Endpoint {path} returned {denied_paths[path]} then 200: {stripped}",
                    time_val,
                )

    if error_count > 10:
        alerts.append(
            make_alert(
                "Exception Storm",
                f"{error_count} Exception/ERROR lines detected in application logs during ZAP phase",
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            )
        )

    return alerts


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: analyze_app_logs.py <app-logs-raw.txt> <runtime-alerts.json>", file=sys.stderr)
        return 1

    log_file = Path(sys.argv[1])
    out_file = Path(sys.argv[2])

    lines: list[str] = []
    if log_file.exists() and log_file.stat().st_size > 0:
        lines = log_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()

    alerts = analyze_logs(lines)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"[Runtime] {len(alerts)} alert(s) detected from {len(lines)} log line(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
