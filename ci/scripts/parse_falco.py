#!/usr/bin/env python3
"""Filter Falco JSON log lines for alerts targeting a specific container."""
import json
import sys
from pathlib import Path


def event_matches_target(evt: dict, target: str) -> bool:
    output = evt.get("output", "") or ""
    fields = evt.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    cname = fields.get("container.name", "") or ""
    if cname == target:
        return True
    if target in output:
        return True
    if f"container={target}" in output or f"container_name={target}" in output:
        return True
    return False


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "Usage: parse_falco.py <raw_json_lines> <out_file> <target_container>",
            file=sys.stderr,
        )
        return 1

    raw_file = Path(sys.argv[1])
    out_file = Path(sys.argv[2])
    target = sys.argv[3]

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
            if isinstance(evt, dict) and event_matches_target(evt, target):
                alerts.append(evt)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"[Falco] {len(alerts)} alert(s) found for container '{target}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
