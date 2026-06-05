#!/usr/bin/env python3
"""Filter Falco JSON log lines for alerts targeting the application container."""
import json
import re
import sys
from pathlib import Path

DOCKER_PRINT_SCRIPTS = (
    "filter_zap",
    "print_zap",
    "print_trivy",
    "print_sonar",
    "print_gitleaks",
)

INVALID_CONTAINER_IDS = {"", "<na>", "na", "null", "none", "host"}


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
    return str(value).strip()


def normalize_container_id(value: str) -> str:
    cid = (value or "").strip().lower().removeprefix("sha256:")
    if cid in INVALID_CONTAINER_IDS:
        return ""
    return cid


def event_container_ids(evt: dict) -> list[str]:
    fields = evt.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    ids: list[str] = []
    for key in ("container.id", "container.full_id", "container_id"):
        normalized = normalize_container_id(_field_str(fields, key))
        if normalized and normalized not in ids:
            ids.append(normalized)

    output = evt.get("output") or ""
    for match in re.findall(r"\b[a-f0-9]{12,64}\b", output.lower()):
        normalized = normalize_container_id(match)
        if normalized and normalized not in ids:
            ids.append(normalized)

    return ids


def container_id_matches_prefix(evt: dict, prefix: str) -> bool:
    if not prefix:
        return False

    for cid in event_container_ids(evt):
        if cid.startswith(prefix) or prefix.startswith(cid[:12]):
            return True

    output = (evt.get("output") or "").lower()
    if prefix in output:
        return True

    return False


def is_ci_noise(evt: dict, target: str) -> bool:
    """Suppress known pipeline false positives (Jenkins, ZAP sidecars, healthchecks)."""
    fields = evt.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    cmdline = _field_str(fields, "proc.cmdline").lower()
    exe = _field_str(fields, "proc.exe").lower()
    output = (evt.get("output") or "").lower()
    proc_name = _field_str(fields, "proc.name").lower()
    target_lower = target.lower()

    if "docker inspect" in cmdline and target_lower in cmdline:
        return True
    if "ping -c 1" in cmdline or (proc_name == "ping" and "-c" in cmdline and " 1" in cmdline):
        return True
    if "docker logs falco-runtime" in cmdline or (
        "docker logs" in cmdline and "falco-runtime" in cmdline
    ):
        return True
    if "selenium-manager" in cmdline or "selenium-manager" in output:
        return True
    if proc_name == "docker" or exe.endswith("/docker") or exe == "docker":
        if any(script in cmdline for script in DOCKER_PRINT_SCRIPTS):
            return True

    return False


def event_matches_target(evt: dict, target: str, container_id_prefix: str | None) -> bool:
    """Match app-archivage events by container ID prefix (DinD-safe)."""
    fields = evt.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    if container_id_prefix:
        if container_id_matches_prefix(evt, container_id_prefix):
            return True
        if normalize_container_id(_field_str(fields, "container.name")) == target.lower():
            return True
        return False

    output_lower = (evt.get("output") or "").lower()
    if normalize_container_id(_field_str(fields, "container.name")) == target.lower():
        return True
    if target in output_lower or f"container={target}" in output_lower:
        return True

    cmdline_lower = _field_str(fields, "proc.cmdline").lower()
    for keyword in ("archivage", "spring", "8090"):
        if keyword in cmdline_lower:
            return True
    for keyword in ("app-archivage", "8090", "archivage"):
        if keyword in output_lower:
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
        print(f"[Falco] Container ID prefix: {container_id_prefix} (match by container.id, any rule)")
    else:
        print("[Falco] No container ID file — using name/output/cmdline fallback")

    alerts: list[dict] = []
    suppressed = 0
    if raw_file.exists() and raw_file.stat().st_size > 0:
        for line in raw_file.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(evt, dict):
                continue
            if not event_matches_target(evt, target, container_id_prefix):
                continue
            if is_ci_noise(evt, target):
                suppressed += 1
                continue
            alerts.append(evt)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"[Falco] {len(alerts)} alert(s) found for container '{target}' ({suppressed} CI noise suppressed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
