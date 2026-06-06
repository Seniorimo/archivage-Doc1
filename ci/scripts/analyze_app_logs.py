#!/usr/bin/env python3
"""Analyze Spring Boot container logs for suspicious runtime patterns during ZAP."""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SQL_INJECTION_PATTERNS = (
    re.compile(r"OR\s+'1'\s*=\s*'1'", re.I),
    re.compile(r"OR\s+1\s*=\s*1", re.I),
    re.compile(r"UNION\s+SELECT", re.I),
    re.compile(r"DROP\s+TABLE", re.I),
    re.compile(r"';?\s*--", re.I),
)

PATH_TRAVERSAL_PATTERNS = (
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/"),
    re.compile(r"/proc/"),
)

STACK_FRAME_RE = re.compile(
    r"^\s*at\s+(?:java\.|com\.|javax\.|org\.|sun\.|jdk\.|[a-zA-Z0-9_.$]+)",
    re.I,
)

EXCEPTION_CLASS_RE = re.compile(
    r"(?:Caused by:\s*)?(?:[a-zA-Z0-9_$]+\.)*([A-Z][a-zA-Z0-9_$]*(?:Exception|Error))\b"
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
    return ""


def extract_time_from_context(lines: list[str], idx: int) -> str:
    for j in range(idx, max(-1, idx - 10), -1):
        match = TIME_RE.match(lines[j].strip())
        if match:
            return match.group(1)
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_primary_log_line(line: str) -> bool:
    stripped = line.strip()
    if TIME_RE.match(stripped):
        return True
    return bool(re.search(r"\b(?:INFO|DEBUG|WARN|WARNING|ERROR|TRACE)\b", stripped))


def is_sql_injection_error_response(lines: list[str], idx: int) -> bool:
    line = lines[idx]
    if not (
        re.search(r"JdbcSQLSyntaxErrorException", line, re.I)
        or re.search(r"SQLSyntaxError", line, re.I)
    ):
        return False
    window_text = " ".join(
        lines[j].strip() for j in range(idx, min(len(lines), idx + 3))
    )
    if not (
        re.search(r"OR\s+'", window_text, re.I)
        or re.search(r"UNION", window_text, re.I)
        or re.search(r"'='", window_text, re.I)
    ):
        return False
    context = " ".join(
        lines[j].strip() for j in range(max(0, idx - 2), min(len(lines), idx + 3))
    )
    return bool(
        re.search(r"\bERROR\b", context, re.I)
        or re.search(r"JdbcSQLSyntaxErrorException", context, re.I)
        or re.search(r"SQLSyntaxError", context, re.I)
    )


def extract_path(line: str) -> str | None:
    for match in HTTP_PATH_RE.finditer(line):
        path = match.group(1) or match.group(2)
        if path and path.startswith("/"):
            return path.split("?")[0]
    uri_match = re.search(r"uri=([^\s,]+)|path=([^\s,]+)", line, re.I)
    if uri_match:
        return (uri_match.group(1) or uri_match.group(2)).split("?")[0]
    return None


def extract_exception_class(line: str) -> str | None:
    match = EXCEPTION_CLASS_RE.search(line)
    return match.group(1) if match else None


def is_stack_frame(line: str) -> bool:
    return bool(STACK_FRAME_RE.match(line))


def detect_grouped_stack_traces(lines: list[str]) -> list[tuple[int, int, str, str]]:
    """Return (start_idx, end_idx, time, exception_short_name) for each stack trace block."""
    blocks: list[tuple[int, int, str, str]] = []
    i = 0
    while i < len(lines):
        if not is_stack_frame(lines[i]):
            i += 1
            continue
        start = i
        while i < len(lines) and is_stack_frame(lines[i]):
            i += 1
        end = i - 1
        exc_name = None
        for j in range(start - 1, max(-1, start - 15), -1):
            exc_name = extract_exception_class(lines[j])
            if exc_name:
                break
        time_val = extract_time_from_context(lines, start)
        blocks.append((start, end, time_val, exc_name or "UnknownException"))
    return blocks


def make_alert(rule: str, output: str, time: str, priority: str = "WARNING") -> dict:
    return {
        "time": time,
        "priority": priority,
        "rule": rule,
        "output": output[:500],
    }


def parse_alert_time(time_str: str) -> datetime | None:
    raw = time_str.strip()
    if raw.endswith(" UTC"):
        raw = raw[:-4].strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_sql_payload(output: str) -> str:
    normalized = re.sub(r"\s+", " ", output).strip()
    select_match = re.search(
        r"SELECT\b.+?(?:OR\s+'1'\s*=\s*'1'|OR\s+1\s*=\s*1|UNION\s+SELECT|DROP\s+TABLE|';?\s*--)",
        normalized,
        re.I,
    )
    if select_match:
        return re.sub(r"\s+", " ", select_match.group(0)).lower()
    markers = []
    for pattern in SQL_INJECTION_PATTERNS:
        match = pattern.search(normalized)
        if match:
            markers.append(re.sub(r"\s+", " ", match.group(0)).lower())
    return "|".join(sorted(set(markers))) if markers else normalized[:120].lower()


def dedupe_near_duplicate_alerts(alerts: list[dict]) -> list[dict]:
    """Drop later alerts with same rule, payload, and timestamp within 1 second."""
    kept: list[dict] = []
    for alert in alerts:
        is_duplicate = False
        alert_time = parse_alert_time(alert.get("time", ""))
        alert_payload = extract_sql_payload(alert.get("output", ""))
        for prior in kept:
            if prior.get("rule") != alert.get("rule"):
                continue
            prior_payload = extract_sql_payload(prior.get("output", ""))
            if not alert_payload or alert_payload != prior_payload:
                continue
            prior_time = parse_alert_time(prior.get("time", ""))
            if alert_time and prior_time:
                if abs((alert_time - prior_time).total_seconds()) <= 1:
                    is_duplicate = True
                    break
            elif alert_payload == prior_payload:
                is_duplicate = True
                break
        if not is_duplicate:
            kept.append(alert)
    return kept


def analyze_logs(lines: list[str]) -> list[dict]:
    alerts: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, output: str, time: str, priority: str = "WARNING") -> None:
        key = (rule, output[:200])
        if key in seen:
            return
        seen.add(key)
        alerts.append(make_alert(rule, output, time, priority))

    stack_blocks = detect_grouped_stack_traces(lines)
    stack_line_indices = set()
    exception_line_indices = set()
    for start, end, time_val, exc_name in stack_blocks:
        for idx in range(start, end + 1):
            stack_line_indices.add(idx)
        for j in range(start - 1, max(-1, start - 15), -1):
            if extract_exception_class(lines[j]):
                exception_line_indices.add(j)
                break
        add(
            "Stack Trace Detected",
            f"Stack Trace Detected: {exc_name}",
            time_val,
        )

    error_count = 0
    denied_paths: dict[str, str] = {}
    sql_error_handled: set[int] = set()

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        time_val = extract_time_from_context(lines, idx) if not extract_time(stripped) else extract_time(stripped)

        if idx not in stack_line_indices:
            if is_primary_log_line(stripped) and any(
                pattern.search(stripped) for pattern in SQL_INJECTION_PATTERNS
            ):
                add("SQL Injection Attempt", stripped, time_val, "CRITICAL")

            if idx not in sql_error_handled and is_sql_injection_error_response(lines, idx):
                window_parts: list[str] = []
                for j in range(idx, min(len(lines), idx + 3)):
                    if is_stack_frame(lines[j]):
                        break
                    part = lines[j].strip()
                    if part:
                        window_parts.append(part)
                output = " ".join(window_parts)[:500]
                add("SQL Injection Error Response", output, time_val, "CRITICAL")
                for j in range(idx, min(len(lines), idx + 3)):
                    sql_error_handled.add(j)

            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(stripped):
                    add("Path Traversal Attempt", stripped, time_val)
                    break

            exc_name = extract_exception_class(stripped)
            if (
                exc_name
                and not is_stack_frame(stripped)
                and idx not in exception_line_indices
            ):
                next_is_frame = idx + 1 < len(lines) and is_stack_frame(lines[idx + 1])
                if not next_is_frame:
                    add(
                        "Stack Trace Detected",
                        f"Stack Trace Detected: {exc_name}",
                        time_val,
                    )

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

    return dedupe_near_duplicate_alerts(alerts)


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: analyze_app_logs.py <app-logs-raw.txt> <runtime-alerts.json>", file=sys.stderr)
        return 1

    log_file = Path(sys.argv[1])
    out_file = Path(sys.argv[2])

    line_count = 0
    if not log_file.exists() or log_file.stat().st_size == 0:
        alerts = [
            make_alert(
                "Log Collection Failed",
                "app-logs-raw.txt is missing or empty — docker logs may have failed or ran before the app container produced output",
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "WARNING",
            )
        ]
    else:
        lines = log_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        line_count = len(lines)
        alerts = analyze_logs(lines)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"[Runtime] {len(alerts)} alert(s) detected from {line_count} log line(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
