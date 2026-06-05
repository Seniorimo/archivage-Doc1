#!/usr/bin/env python3
"""Filter Falco JSON log lines for alerts targeting the application container."""
import json
import sys
from pathlib import Path

APP_OUTPUT_KEYWORDS = ("app-archivage", "8090", "archivage")
APP_CMDLINE_KEYWORDS = ("archivage", "spring", "8090")


def load_container_id_prefix(id_file: Path) -> str | None:
    if not id_file.exists() or id_file.stat().st_size == 0:
        return None
    raw_id = id_file.read_text(encoding="utf-8-sig", errors="replace").strip()
    raw_id = raw_id.removeprefix("sha256:")
    if not raw_id:
        return None
    return raw_id[:12].lower()


def _field_str(fields: dict, key: str) -> str:
    value = fields.get(key)
    if value is None:
        return ""
    return str(value)


def event_matches_target(evt: dict, target: str, container_id_prefix: str | None) -> bool:
    output = (evt.get("output") or "")
    output_lower = output.lower()
    fields = evt.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    if container_id_prefix:
        container_id = _field_str(fields, "container.id").lower()
        if container_id and container_id.startswith(container_id_prefix):
            return True

    if target in output or _field_str(fields, "container.name") == target:
        return True
    if f"container={target}" in output or f"container_name={target}" in output:
        return True

    cmdline_lower = _field_str(fields, "proc.cmdline").lower()
    if container_id_prefix:
        for keyword in APP_CMDLINE_KEYWORDS:
            if keyword in cmdline_lower:
                return True
        return False

    for keyword in APP_OUTPUT_KEYWORDS:
        if keyword in output_lower:
            return True
    for keyword in APP_CMDLINE_KEYWORDS:
        if keyword in cmdline_lower:
            return True
    return False


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "Usage: parse_falco.py <raw_json_lines> <out_file> <target_container> [container_id_file]",
            file=sys.stderr,
        )
        return 1

    raw_file = Path(sys.argv[1])
    out_file = Path(sys.argv[2])
    target = sys.argv[3]
    id_file = Path(sys.argv[4]) if len(sys.argv) > 4 else raw_file.parent / "app-container-id.txt"

    container_id_prefix = load_container_id_prefix(id_file)
    if container_id_prefix:
        print(f"[Falco] Container ID prefix: {container_id_prefix}")
    else:
        print("[Falco] No container ID file — using output/cmdline fallback keywords")

    alerts: list[dict] = []
    if raw_file.exists() and raw_file.stat().st_size > 0:
        for line in raw_file.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(evt, dict) and event_matches_target(evt, target, container_id_prefix):
                alerts.append(evt)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"[Falco] {len(alerts)} alert(s) found for container '{target}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
