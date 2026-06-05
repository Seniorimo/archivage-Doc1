#!/usr/bin/env python3
"""
generate_dashboard.py  — Enhanced DevSecOps Security Dashboard
──────────────────────────────────────────────────────────────
Génère un dashboard HTML complet à partir des rapports de sécurité
produits par le pipeline DevSecOps (Jenkins / GitHub Actions).

Briques couvertes :
  • Gitleaks   — secrets détectés        (gitleaks-report.json)
  • Trivy      — vulnérabilités SCA/FS   (trivy-report.json)
  • OWASP ZAP  — alertes DAST           (zap-report.json)
  • CycloneDX  — inventaire SBOM        (bom.json)
  • OPA        — résultat security gate  (opa-result.txt + input.json)
  • Falco      — alertes runtime        (falco-alerts.txt)
  • SonarQube  — qualité code           (API REST optionnelle)

Usage :
  python generate_dashboard.py
  python generate_dashboard.py --reports ./my-reports
  python generate_dashboard.py --reports ./r --sonar-url http://localhost:9000 \\
         --sonar-token squ_xxx --sonar-project archivage-Doc
  python generate_dashboard.py --serve
"""

import argparse
import html
import json
import os
import re
import sys
import webbrowser
import http.server
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError


# ═══════════════════════════════════════════════════════════════════════════════
# PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

def load_json(path: Path, default):
    if not path.exists() or path.stat().st_size == 0:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  [WARN] Impossible de lire {path}: {e}", file=sys.stderr)
        return default


def parse_gitleaks(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "gitleaks" / "gitleaks-report.json", [])
    if not isinstance(data, list):
        data = []
    findings = []
    for item in data:
        findings.append({
            "rule":   item.get("RuleID", "?"),
            "file":   item.get("File", "?"),
            "line":   item.get("StartLine", "?"),
            "commit": str(item.get("Commit", ""))[:8] or "—",
            "author": item.get("Author", "—"),
            "date":   item.get("Date", "—")[:10] if item.get("Date") else "—",
            "secret": item.get("Secret", "")[:40] + ("…" if len(item.get("Secret", "")) > 40 else ""),
            "tags":   item.get("Tags", []),
        })
    return {"count": len(findings), "findings": findings}


def parse_trivy(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "trivy" / "trivy-report.json", {"Results": []})
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulns = []
    targets_seen = set()
    targets = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        rtype  = result.get("Type", "")
        if target not in targets_seen:
            targets_seen.add(target)
            targets.append({"target": target, "type": rtype})
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            refs = v.get("References", []) or []
            vulns.append({
                "id":          v.get("VulnerabilityID", "?"),
                "pkg":         v.get("PkgName", "?"),
                "installed":   v.get("InstalledVersion", "?"),
                "fixed":       v.get("FixedVersion", "—"),
                "severity":    sev,
                "title":       (v.get("Title") or v.get("Description") or "")[:160],
                "target":      target,
                "cvss":        _extract_cvss(v),
                "refs":        refs[:2],
            })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda x: order.get(x["severity"], 9))
    return {
        "counts": sev_counts,
        "total": sum(sev_counts.values()),
        "vulns": vulns,
        "targets": targets,
        "schema_version": data.get("SchemaVersion", ""),
        "artifact_name": data.get("ArtifactName", ""),
        "artifact_type": data.get("ArtifactType", ""),
    }


def _extract_cvss(v: dict) -> str:
    cvss = v.get("CVSS") or {}
    for src in ("nvd", "redhat", "ghsa"):
        if src in cvss:
            score = cvss[src].get("V3Score") or cvss[src].get("V2Score")
            if score:
                return str(score)
    return "—"


def parse_zap(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "zap" / "zap-report.json",
                     {"site": [{"alerts": []}]})
    risk_map = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    alerts = []
    target = ""
    zap_version = data.get("@version", "")
    generated   = data.get("@generated", "")
    for site in data.get("site", []) or []:
        if not target:
            target = site.get("@name", site.get("name", ""))
        for a in site.get("alerts", []) or []:
            rc = int(a.get("riskcode", 0))
            label = risk_map.get(rc, "INFO")
            counts[label] = counts.get(label, 0) + 1
            instances = a.get("instances") or []
            urls = [i.get("uri", "") for i in instances[:3]]
            alerts.append({
                "name":       a.get("alert", a.get("name", "?")),
                "risk":       label,
                "riskcode":   rc,
                "urls":       urls,
                "desc":       (a.get("desc") or "")[:300],
                "solution":   (a.get("solution") or "")[:300],
                "reference":  (a.get("reference") or "")[:200],
                "cweid":      a.get("cweid", ""),
                "wascid":     a.get("wascid", ""),
                "count":      int(a.get("count", len(instances) or 1)),
                "confidence": a.get("confidence", ""),
            })
    alerts.sort(key=lambda x: -x["riskcode"])
    return {
        "target":      target,
        "counts":      counts,
        "total":       sum(counts.values()),
        "alerts":      alerts,
        "zap_version": zap_version,
        "generated":   generated,
    }


def parse_sbom(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "sbom" / "bom.json", {})
    components = data.get("components", []) or []
    by_type: dict = {}
    for c in components:
        t = c.get("type", "library")
        by_type[t] = by_type.get(t, 0) + 1
    comp_list = []
    for c in components[:500]:
        licenses = []
        for lic in (c.get("licenses") or []):
            expr = lic.get("expression") or (lic.get("license") or {}).get("id", "")
            if expr:
                licenses.append(expr)
        comp_list.append({
            "name":     c.get("name", "?"),
            "version":  c.get("version", "—"),
            "type":     c.get("type", "library"),
            "purl":     c.get("purl", ""),
            "licenses": ", ".join(licenses) or "—",
            "group":    c.get("group", ""),
        })
    metadata = data.get("metadata", {}) or {}
    return {
        "total":        len(components),
        "by_type":      by_type,
        "components":   comp_list,
        "spec_version": data.get("specVersion", "—"),
        "serial":       data.get("serialNumber", "—"),
        "bom_version":  str(data.get("version", "1")),
        "tool_name":    ((metadata.get("tools") or [{}])[0]).get("name", "—") if metadata.get("tools") else "—",
        "timestamp":    metadata.get("timestamp", ""),
        "component_name": (metadata.get("component") or {}).get("name", ""),
        "component_version": (metadata.get("component") or {}).get("version", ""),
    }


FALCO_TS_PREFIX = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}[T\s][^\s]+\s+|\d{1,2}:\d{2}:\d{2}(?:\.\d+)?:\s*)",
    re.IGNORECASE,
)
FALCO_SEVERITY_RE = re.compile(
    r"^(Critical|Warning|Error|Notice|Informational|Debug|Emergency|Alert)\s*:?\s*",
    re.IGNORECASE,
)
FALCO_KV_RE = re.compile(
    r"\b([a-z][a-z0-9_.]*)\s*=\s*([^)\s|]+(?:\([^)]*\))?[^)\s|]*)",
    re.IGNORECASE,
)


def _normalize_falco_severity(value: str) -> str:
    sev = (value or "UNKNOWN").strip().upper()
    if sev == "INFORMATIONAL":
        return "INFO"
    return sev


def _parse_falco_line(line: str) -> dict:
    """Parse one Falco log line; fall back gracefully on malformed input."""
    raw = line.strip()
    if not raw:
        return {
            "severity": "UNKNOWN",
            "message": "",
            "metadata": "",
            "raw": raw,
            "dedup_key": "",
        }

    body = FALCO_TS_PREFIX.sub("", raw, count=1).strip()
    severity = "UNKNOWN"
    match = FALCO_SEVERITY_RE.match(body)
    if match:
        severity = _normalize_falco_severity(match.group(1))
        body = body[match.end():].strip()
    else:
        for token in ("Critical", "Warning", "Error", "Notice", "Emergency", "Alert"):
            idx = body.lower().find(token.lower())
            if idx != -1 and idx < 40:
                severity = _normalize_falco_severity(token)
                body = (body[:idx] + body[idx + len(token):]).lstrip(" :")
                break

    message = body
    metadata = ""
    if " | " in body:
        message, metadata = [part.strip() for part in body.split(" | ", 1)]
    elif "(" in body and ")" in body:
        open_idx = body.find("(")
        message = body[:open_idx].strip()
        metadata = body[open_idx:].strip()
    else:
        kv_hits = FALCO_KV_RE.findall(body)
        if kv_hits:
            first_kv = body.find(f"{kv_hits[0][0]}=")
            if first_kv > 0:
                message = body[:first_kv].strip()
                metadata = body[first_kv:].strip()

    if not message:
        message = raw
    if not metadata and message != raw:
        metadata = raw[len(message):].strip(" |()")

    dedup_key = re.sub(r"\s+", " ", f"{severity}|{message}|{metadata}".lower()).strip()
    return {
        "severity": severity,
        "message": message,
        "metadata": metadata,
        "raw": raw,
        "dedup_key": dedup_key or raw.lower(),
    }


def parse_falco(reports_dir: Path) -> dict:
    path = reports_dir / "runtime" / "falco-alerts.txt"
    exists = path.exists()
    raw_lines: list[str] = []

    if exists and path.stat().st_size > 0:
        try:
            text = path.read_text(encoding="utf-8-sig")
            raw_lines = [
                line.strip().lstrip("\ufeff")
                for line in text.splitlines()
                if line.strip()
            ]
        except Exception as e:
            print(f"  [WARN] Impossible de lire {path}: {e}", file=sys.stderr)

    grouped: dict[str, dict] = {}
    for line in raw_lines:
        parsed = _parse_falco_line(line)
        key = parsed["dedup_key"]
        if key not in grouped:
            grouped[key] = {
                "severity": parsed["severity"],
                "message": parsed["message"],
                "metadata": parsed["metadata"],
                "count": 0,
                "sample": parsed["raw"],
            }
        entry = grouped[key]
        entry["count"] += 1
        if len(parsed["raw"]) > len(entry.get("sample", "")):
            entry["sample"] = parsed["raw"]

    groups = sorted(grouped.values(), key=lambda g: (-g["count"], g["severity"], g["message"]))
    total = len(raw_lines)
    unique_count = len(groups)

    return {
        "exists": exists,
        "count": total,
        "unique_count": unique_count,
        "groups": groups,
    }


def parse_opa(reports_dir: Path) -> dict:
    result_file = reports_dir / "opa" / "opa-result.txt"
    input_file  = reports_dir / "opa" / "input.json"
    passed = None
    raw_result = ""
    if result_file.exists():
        raw_result = result_file.read_text(encoding="utf-8").strip()
        if raw_result == "true":
            passed = True
        elif raw_result == "false":
            passed = False
    opa_input = load_json(input_file, {})
    return {"passed": passed, "input": opa_input, "raw": raw_result}


def fetch_sonarqube(sonar_url: str, sonar_token: str, project_key: str) -> dict | None:
    if not sonar_url or not project_key:
        return None
    try:
        import base64
        credentials = base64.b64encode(f"{sonar_token}:".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}"}

        def api_get(path):
            req = Request(f"{sonar_url.rstrip('/')}{path}", headers=headers)
            with urlopen(req, timeout=8) as r:
                return json.loads(r.read().decode())

        measures_resp = api_get(
            f"/api/measures/component?component={project_key}"
            "&metricKeys=bugs,vulnerabilities,code_smells,coverage,"
            "duplicated_lines_density,ncloc,security_hotspots,alert_status,"
            "reliability_rating,security_rating,sqale_rating"
        )
        metrics = {}
        for m in measures_resp.get("component", {}).get("measures", []):
            metrics[m["metric"]] = m.get("value", "—")

        gate_resp = api_get(f"/api/qualitygates/project_status?projectKey={project_key}")
        gate = gate_resp.get("projectStatus", {})

        issues_resp = api_get(
            f"/api/issues/search?componentKeys={project_key}&types=VULNERABILITY&ps=20"
        )
        issues = issues_resp.get("issues", [])

        return {
            "metrics":     metrics,
            "gate_status": gate.get("status", "NONE"),
            "conditions":  gate.get("conditions", []),
            "url":         f"{sonar_url.rstrip('/')}/dashboard?id={project_key}",
            "issues":      issues,
        }
    except (URLError, Exception) as e:
        print(f"  [WARN] SonarQube inaccessible : {e}", file=sys.stderr)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# HTML HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

SEV_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fca5a5", "#fee2e2"),  # dark-bg, dark-text, light-bg
    "HIGH":     ("#7c2d12", "#fdba74", "#ffedd5"),
    "MEDIUM":   ("#713f12", "#fcd34d", "#fef9c3"),
    "LOW":      ("#14532d", "#86efac", "#dcfce7"),
    "UNKNOWN":  ("#1e3a5f", "#93c5fd", "#dbeafe"),
    "INFO":     ("#1e3a5f", "#93c5fd", "#dbeafe"),
}

SEV_HEX_DARK = {
    "CRITICAL": "#f87171", "HIGH": "#fb923c",
    "MEDIUM":   "#fbbf24", "LOW":  "#4ade80",
    "UNKNOWN":  "#60a5fa", "INFO": "#60a5fa",
}
SEV_HEX_LIGHT = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM":   "#d97706", "LOW":  "#16a34a",
    "UNKNOWN":  "#2563eb", "INFO": "#2563eb",
}


def _sev_pill(sev: str, mode="dark") -> str:
    colors = {
        "dark": {
            "CRITICAL": ("rgba(239,68,68,0.15)", "#f87171", "rgba(239,68,68,0.3)"),
            "HIGH":     ("rgba(249,115,22,0.15)","#fb923c","rgba(249,115,22,0.3)"),
            "MEDIUM":   ("rgba(234,179,8,0.15)", "#facc15","rgba(234,179,8,0.3)"),
            "LOW":      ("rgba(34,197,94,0.15)", "#4ade80","rgba(34,197,94,0.3)"),
            "UNKNOWN":  ("rgba(96,165,250,0.15)","#60a5fa","rgba(96,165,250,0.3)"),
            "INFO":     ("rgba(96,165,250,0.15)","#60a5fa","rgba(96,165,250,0.3)"),
        }
    }
    c = colors["dark"].get(sev.upper(), colors["dark"]["UNKNOWN"])
    return (
        f'<span style="background:{c[0]};color:{c[1]};border:1px solid {c[2]};'
        f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;'
        f'letter-spacing:0.06em;font-family:var(--mono);white-space:nowrap">{sev}</span>'
    )


def _risk_pill(risk: str) -> str:
    return _sev_pill(risk)


def _tag(text: str, color="#334155") -> str:
    return (
        f'<span style="background:rgba(255,255,255,0.06);color:var(--text-muted);'
        f'border:1px solid rgba(255,255,255,0.1);padding:1px 6px;border-radius:3px;'
        f'font-size:10px;font-family:var(--mono)">{text}</span>'
    )


def _empty(msg="Aucune donnée détectée") -> str:
    return (
        f'<div style="text-align:center;padding:48px 24px;color:var(--text-muted);'
        f'font-size:13px;border:1px dashed rgba(255,255,255,0.1);border-radius:8px">'
        f'<div style="font-size:32px;margin-bottom:8px">✓</div>{msg}</div>'
    )


def _section(icon: str, title: str, subtitle: str = "") -> str:
    sub = f'<span style="color:var(--text-muted);font-size:12px;margin-left:auto">{subtitle}</span>' if subtitle else ""
    return (
        f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;'
        f'padding-bottom:12px;border-bottom:1px solid var(--border)">'
        f'<span style="font-size:18px">{icon}</span>'
        f'<h2 style="font-size:13px;font-weight:700;letter-spacing:0.08em;'
        f'text-transform:uppercase;color:var(--text)">{title}</h2>{sub}</div>'
    )


def _stat_card(label: str, value, color: str = "var(--accent)", note: str = "") -> str:
    note_html = f'<div style="font-size:10px;color:var(--text-muted);margin-top:2px">{note}</div>' if note else ""
    return (
        f'<div class="stat-card" style="border-top:2px solid {color}">'
        f'<div style="font-size:28px;font-weight:800;font-family:var(--mono);'
        f'color:{color};line-height:1">{value}</div>'
        f'<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;'
        f'letter-spacing:0.06em;margin-top:6px">{label}</div>{note_html}</div>'
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION RENDERERS — full inline report display
# ═══════════════════════════════════════════════════════════════════════════════

def render_overview(gitleaks, trivy, zap, sbom, opa, falco) -> str:
    opa_ok = opa["passed"]
    if (
        opa_ok is False
        or gitleaks["count"] > 0
        or trivy["counts"].get("CRITICAL", 0) > 0
        or falco["count"] > 0
    ):
        overall_color, overall_label, overall_icon = "#ef4444", "AT RISK", "🔴"
    elif trivy["counts"].get("HIGH", 0) > 0 or zap["counts"].get("HIGH", 0) > 0:
        overall_color, overall_label, overall_icon = "#f97316", "WARNING", "🟡"
    else:
        overall_color, overall_label, overall_icon = "#22c55e", "SECURE", "🟢"

    opa_label = "PASS" if opa_ok else ("FAIL" if opa_ok is False else "N/A")
    opa_color = "#22c55e" if opa_ok else ("#ef4444" if opa_ok is False else "#64748b")

    hero = f"""
<div style="background:rgba(255,255,255,0.03);border:1px solid {overall_color}33;
  border-left:3px solid {overall_color};border-radius:10px;
  padding:24px 28px;margin-bottom:32px;display:flex;align-items:center;gap:24px;flex-wrap:wrap">
  <div style="font-size:42px">{overall_icon}</div>
  <div>
    <div style="font-size:26px;font-weight:900;letter-spacing:0.05em;color:{overall_color}">{overall_label}</div>
    <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Statut global de sécurité du pipeline</div>
  </div>
  <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">
    <div style="background:{opa_color}22;border:1px solid {opa_color}55;
      border-radius:6px;padding:8px 16px;text-align:center">
      <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em">OPA Gate</div>
      <div style="font-size:16px;font-weight:800;color:{opa_color};font-family:var(--mono)">{opa_label}</div>
    </div>
  </div>
</div>"""

    # Stat grid
    c = trivy["counts"]
    z = zap["counts"]
    stats = (
        _stat_card("Secrets", gitleaks["count"], "#ef4444" if gitleaks["count"] > 0 else "#22c55e") +
        _stat_card("CVE Critical", c.get("CRITICAL", 0), "#ef4444" if c.get("CRITICAL",0) > 0 else "#22c55e") +
        _stat_card("CVE High", c.get("HIGH", 0), "#f97316" if c.get("HIGH",0) > 0 else "#22c55e") +
        _stat_card("CVE Medium", c.get("MEDIUM", 0), "#eab308") +
        _stat_card("CVE Low", c.get("LOW", 0), "#64748b") +
        _stat_card("ZAP High", z.get("HIGH", 0), "#ef4444" if z.get("HIGH",0) > 0 else "#22c55e") +
        _stat_card("ZAP Medium", z.get("MEDIUM", 0), "#f97316") +
        _stat_card(
            "Runtime (Falco)",
            falco["count"],
            "#ef4444" if falco["count"] > 0 else "#22c55e",
            note=(
                f"{falco.get('unique_count', falco['count'])} signature(s) unique(s)"
                if falco["count"] > 0 else "Alertes pendant l'attaque ZAP"
            ),
        ) +
        _stat_card("Composants", sbom["total"], "#3b82f6")
    )

    stat_grid = f'<div class="stat-grid">{stats}</div>'

    # Breakdown bars
    total_trivy = trivy["total"] or 1
    breakdown = '<div style="margin-top:28px">'
    breakdown += f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:12px">Répartition des vulnérabilités Trivy</div>'
    for sev, color in [("CRITICAL","#ef4444"),("HIGH","#f97316"),("MEDIUM","#eab308"),("LOW","#22c55e"),("UNKNOWN","#3b82f6")]:
        n = c.get(sev, 0)
        pct = round(n / total_trivy * 100)
        breakdown += f"""
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <div style="width:80px;font-size:11px;font-weight:700;color:{color}">{sev}</div>
  <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:4px;height:8px;overflow:hidden">
    <div style="width:{pct}%;background:{color};height:100%;border-radius:4px;transition:width 0.6s ease"></div>
  </div>
  <div style="width:50px;text-align:right;font-family:var(--mono);font-size:12px;color:var(--text-muted)">{n}</div>
</div>"""
    breakdown += '</div>'

    # ZAP breakdown
    total_zap = zap["total"] or 1
    breakdown += '<div style="margin-top:20px">'
    breakdown += f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:12px">Répartition des alertes OWASP ZAP</div>'
    for risk, color in [("HIGH","#ef4444"),("MEDIUM","#f97316"),("LOW","#22c55e"),("INFO","#3b82f6")]:
        n = z.get(risk, 0)
        pct = round(n / total_zap * 100)
        breakdown += f"""
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <div style="width:80px;font-size:11px;font-weight:700;color:{color}">{risk}</div>
  <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:4px;height:8px;overflow:hidden">
    <div style="width:{pct}%;background:{color};height:100%;border-radius:4px"></div>
  </div>
  <div style="width:50px;text-align:right;font-family:var(--mono);font-size:12px;color:var(--text-muted)">{n}</div>
</div>"""
    breakdown += '</div>'

    return hero + stat_grid + breakdown


def render_gitleaks(gl: dict) -> str:
    if not gl["findings"]:
        return _empty("Aucun secret détecté — le dépôt est propre ✓")

    rows = ""
    for f in gl["findings"]:
        masked = "•" * min(len(f["secret"]), 8) + f["secret"][-4:] if f["secret"] else "—"
        rows += f"""
<tr>
  <td>{_sev_pill("CRITICAL")}</td>
  <td><span style="font-family:var(--mono);font-size:11px;color:var(--accent)">{f["rule"]}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px">{f["file"]}</span>
      <span style="color:var(--text-muted);font-size:11px">:{f["line"]}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">{f["commit"]}</span></td>
  <td><span style="font-size:11px;color:var(--text-muted)">{f["author"]}</span></td>
  <td><span style="font-size:11px;color:var(--text-muted)">{f["date"]}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px;color:#f87171;
      background:rgba(239,68,68,0.1);padding:2px 6px;border-radius:3px">{masked}</span></td>
</tr>"""

    return f"""
<div class="report-info-bar">
  <span>🔑</span>
  <span><strong>{gl["count"]}</strong> secret(s) détecté(s) dans l'historique git</span>
  <span style="margin-left:auto;color:#f87171;font-weight:700">⚠ Action requise</span>
</div>
<div class="table-wrap">
<table>
<thead><tr>
  <th>Sévérité</th><th>Règle</th><th>Fichier : Ligne</th>
  <th>Commit</th><th>Auteur</th><th>Date</th><th>Secret (masqué)</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</div>"""


def render_trivy(tv: dict) -> str:
    meta = ""
    if tv.get("artifact_name"):
        meta += f'<div class="report-info-bar"><span>🐳</span><span>Artefact analysé&nbsp;: <strong style="font-family:var(--mono)">{tv["artifact_name"]}</strong></span>'
        if tv.get("artifact_type"):
            meta += f'<span style="margin-left:12px;color:var(--text-muted)">{tv["artifact_type"]}</span>'
        meta += '</div>'

    if tv["targets"]:
        tgt_list = "".join(
            f'<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">'
            f'<span style="font-family:var(--mono);font-size:12px">{t["target"]}</span>'
            f'<span style="margin-left:auto">{_tag(t["type"])}</span></div>'
            for t in tv["targets"]
        )
        meta += f"""
<details style="margin-bottom:16px">
  <summary style="cursor:pointer;font-size:12px;color:var(--text-muted);padding:8px 0">
    {len(tv["targets"])} cible(s) analysée(s) — cliquer pour développer
  </summary>
  <div style="padding:8px 0;border-top:1px solid var(--border);margin-top:4px">{tgt_list}</div>
</details>"""

    if not tv["vulns"]:
        return meta + _empty("Aucune vulnérabilité détectée ✓")

    rows = ""
    for v in tv["vulns"]:
        cvss_html = f'<span style="font-family:var(--mono);font-size:11px;color:#fbbf24">{v["cvss"]}</span>' if v["cvss"] != "—" else '<span style="color:var(--text-muted)">—</span>'
        fix_color = "#4ade80" if v["fixed"] != "—" else "var(--text-muted)"
        refs_html = ""
        for ref in v["refs"]:
            refs_html += f'<a href="{ref}" target="_blank" style="display:block;font-size:10px;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px">{ref}</a>'
        rows += f"""
<tr>
  <td>{_sev_pill(v["severity"])}</td>
  <td><a href="https://nvd.nist.gov/vuln/detail/{v["id"]}" target="_blank"
      style="font-family:var(--mono);font-size:11px;color:var(--accent);text-decoration:none">{v["id"]}</a></td>
  <td><span style="font-size:12px;font-weight:600">{v["pkg"]}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">{v["installed"]}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px;color:{fix_color}">{v["fixed"]}</span></td>
  <td>{cvss_html}</td>
  <td style="max-width:280px"><span style="font-size:11px;color:var(--text-muted)">{v["title"]}</span>{refs_html}</td>
</tr>"""

    return meta + f"""
<div class="table-filter-row">
  <input type="text" id="trivy-q" placeholder="Filtrer CVE, package, sévérité…"
    oninput="filterRows('trivy-q','trivy-body')" class="filter-input">
</div>
<div class="table-wrap">
<table>
<thead><tr>
  <th>Sév.</th><th>CVE</th><th>Package</th>
  <th>Version installée</th><th>Version corrigée</th><th>CVSS</th><th>Description / Référence</th>
</tr></thead>
<tbody id="trivy-body">{rows}</tbody>
</table>
</div>"""


def render_zap(zap: dict) -> str:
    meta = ""
    if zap.get("target"):
        meta += f'<div class="report-info-bar"><span>🌐</span><span>Cible scannée&nbsp;: <strong style="font-family:var(--mono)">{zap["target"]}</strong></span>'
        if zap.get("zap_version"):
            meta += f'<span style="margin-left:auto;color:var(--text-muted)">ZAP {zap["zap_version"]}</span>'
        meta += '</div>'

    if not zap["alerts"]:
        return meta + _empty("Aucune alerte DAST détectée ✓")

    cards = ""
    for a in zap["alerts"]:
        risk_color = {"HIGH":"#ef4444","MEDIUM":"#f97316","LOW":"#22c55e","INFO":"#3b82f6"}.get(a["risk"], "#64748b")
        urls_html = "".join(
            f'<div style="font-family:var(--mono);font-size:10px;color:var(--text-muted);'
            f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{u}</div>'
            for u in a["urls"] if u
        )
        tags_html = ""
        if a["cweid"]:
            tags_html += _tag(f"CWE-{a['cweid']}")
        if a["wascid"]:
            tags_html += " " + _tag(f"WASC-{a['wascid']}")
        if a["confidence"]:
            tags_html += " " + _tag(f"Conf: {a['confidence']}")

        cards += f"""
<div class="alert-card" style="border-left:3px solid {risk_color}">
  <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:10px">
    {_risk_pill(a["risk"])}
    <div style="font-size:13px;font-weight:700;color:var(--text);flex:1">{a["name"]}</div>
    <div style="font-family:var(--mono);font-size:11px;color:var(--text-muted);white-space:nowrap">×{a["count"]}</div>
  </div>
  {f'<div style="margin-bottom:6px">{urls_html}</div>' if urls_html else ''}
  {f'<div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;line-height:1.6">{a["desc"]}</div>' if a["desc"] else ''}
  {f'''<div style="background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:6px;padding:10px 12px;margin-bottom:8px">
    <div style="font-size:10px;font-weight:700;color:#4ade80;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:4px">Solution recommandée</div>
    <div style="font-size:11px;color:var(--text-muted);line-height:1.6">{a["solution"]}</div>
  </div>''' if a["solution"] else ''}
  {f'<div style="display:flex;gap:6px;flex-wrap:wrap">{tags_html}</div>' if tags_html else ''}
</div>"""

    return meta + cards


def render_sbom(sbom: dict) -> str:
    meta_parts = []
    if sbom.get("component_name"):
        meta_parts.append(f'Composant principal&nbsp;: <strong style="font-family:var(--mono)">{sbom["component_name"]} {sbom.get("component_version","")}</strong>')
    if sbom.get("tool_name") and sbom["tool_name"] != "—":
        meta_parts.append(f'Outil&nbsp;: <strong>{sbom["tool_name"]}</strong>')
    if sbom.get("timestamp"):
        meta_parts.append(f'Généré le&nbsp;: <strong>{sbom["timestamp"][:19]}</strong>')

    meta = ""
    if meta_parts:
        meta = f'<div class="report-info-bar"><span>📦</span><span>{" &nbsp;|&nbsp; ".join(meta_parts)}</span></div>'

    type_badges = "".join(
        f'<div class="stat-card" style="border-top:2px solid #3b82f6;padding:10px 14px">'
        f'<div style="font-size:20px;font-weight:800;font-family:var(--mono);color:#3b82f6">{n}</div>'
        f'<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-top:4px">{t}</div>'
        f'</div>'
        for t, n in sbom["by_type"].items()
    )
    type_grid = f'<div class="stat-grid" style="margin-bottom:24px">{type_badges}</div>'

    if not sbom["components"]:
        return meta + type_grid + _empty("Aucun composant dans le SBOM")

    rows = ""
    for c in sbom["components"]:
        purl_html = f'<div style="font-family:var(--mono);font-size:10px;color:var(--text-muted);margin-top:2px;word-break:break-all">{c["purl"]}</div>' if c["purl"] else ""
        rows += f"""
<tr>
  <td>
    <span style="font-size:12px;font-weight:600">{c["name"]}</span>
    {f'<span style="color:var(--text-muted);font-size:11px"> / {c["group"]}</span>' if c["group"] else ''}
    {purl_html}
  </td>
  <td><span style="font-family:var(--mono);font-size:11px">{c["version"]}</span></td>
  <td>{_tag(c["type"])}</td>
  <td><span style="font-size:11px;color:var(--text-muted)">{c["licenses"]}</span></td>
</tr>"""

    trunc = f'<div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">Affichage limité aux 500 premiers composants sur {sbom["total"]}.</div>' if sbom["total"] > 500 else ""
    return meta + type_grid + trunc + f"""
<div class="table-filter-row">
  <input type="text" id="sbom-q" placeholder="Filtrer par nom, version, licence…"
    oninput="filterRows('sbom-q','sbom-body')" class="filter-input">
</div>
<div class="table-wrap">
<table>
<thead><tr><th>Composant / PURL</th><th>Version</th><th>Type</th><th>Licence</th></tr></thead>
<tbody id="sbom-body">{rows}</tbody>
</table>
</div>"""


def _falco_hit_badge(count: int) -> str:
    return (
        f'<span style="background:rgba(239,68,68,0.15);color:#f87171;'
        f'border:1px solid rgba(239,68,68,0.35);padding:3px 10px;border-radius:999px;'
        f'font-size:11px;font-weight:800;font-family:var(--mono);white-space:nowrap">'
        f"×{count}</span>"
    )


def render_falco(falco: dict) -> str:
    count = falco["count"]
    unique_count = falco.get("unique_count", count)
    groups = falco.get("groups", [])
    status_color = "#22c55e" if count == 0 else "#ef4444"
    status_label = "CLEAN ✓" if count == 0 else f"{count} EVENT(S)"
    status_desc = (
        "Aucune alerte runtime détectée pendant la phase d'attaque ZAP."
        if count == 0 else
        f"{unique_count} signature(s) unique(s) regroupée(s) à partir de {count} événement(s) Falco."
    )

    hero = f"""
<div style="background:{status_color}11;border:1px solid {status_color}33;
  border-radius:10px;padding:24px 28px;margin-bottom:24px;
  display:flex;align-items:center;gap:20px">
  <div style="font-size:48px;line-height:1">{"✅" if count == 0 else "🚨"}</div>
  <div>
    <div style="font-size:22px;font-weight:900;font-family:var(--mono);color:{status_color}">{status_label}</div>
    <div style="font-size:13px;color:var(--text-muted);margin-top:4px">{status_desc}</div>
  </div>
</div>"""

    if count == 0:
        if not falco["exists"]:
            return hero + _empty("Fichier falco-alerts.txt absent — aucune alerte runtime enregistrée")
        return hero + _empty("Aucune alerte Falco détectée pendant la phase runtime ✓")

    rows = ""
    for group in groups:
        sev = group.get("severity", "UNKNOWN")
        hits = group.get("count", 1)
        message = html.escape(group.get("message", "—"))
        metadata = html.escape(group.get("metadata", "") or group.get("sample", ""))
        metadata_html = (
            f'<div style="font-family:var(--mono);font-size:11px;color:#94a3b8;'
            f'margin-top:6px;line-height:1.5;word-break:break-word">{metadata}</div>'
            if metadata else ""
        )
        rows += f"""
<tr>
  <td style="vertical-align:top;width:110px">{_sev_pill(sev)}</td>
  <td style="vertical-align:top;width:72px">{_falco_hit_badge(hits)}</td>
  <td style="vertical-align:top">
    <div style="font-size:13px;font-weight:600;color:var(--text)">{message}</div>
    {metadata_html}
  </td>
</tr>"""

    return hero + f"""
<div class="report-info-bar">
  <span>⚡</span>
  <span><strong>{count}</strong> événement(s) · <strong>{unique_count}</strong> signature(s) unique(s)</span>
  <span style="margin-left:auto;color:#ef4444;font-weight:700">⚠ Investigation requise</span>
</div>
<div class="table-wrap">
<table>
<thead><tr>
  <th>Sévérité</th><th>Occurrences</th><th>Message &amp; métadonnées runtime</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</div>"""


def render_opa(opa: dict) -> str:
    passed = opa["passed"]
    inp = opa.get("input", {}) or {}

    status_color = "#22c55e" if passed else ("#ef4444" if passed is False else "#64748b")
    status_label = "PASS ✓" if passed else ("FAIL ✗" if passed is False else "N/A")
    status_desc  = (
        "Le security gate a validé toutes les conditions requises."
        if passed else (
            "Le security gate a échoué. Le déploiement doit être bloqué."
            if passed is False else
            "Résultat du gate non disponible."
        )
    )

    hero = f"""
<div style="background:{status_color}11;border:1px solid {status_color}33;
  border-radius:10px;padding:24px 28px;margin-bottom:24px;
  display:flex;align-items:center;gap:20px">
  <div style="font-size:48px;line-height:1">{"✅" if passed else ("❌" if passed is False else "❓")}</div>
  <div>
    <div style="font-size:22px;font-weight:900;font-family:var(--mono);color:{status_color}">{status_label}</div>
    <div style="font-size:13px;color:var(--text-muted);margin-top:4px">{status_desc}</div>
  </div>
</div>"""

    # Input details
    if inp:
        trivy_in = inp.get("trivy", {}) or {}
        gitleaks_in = inp.get("gitleaks", []) or []
        zap_in = inp.get("zap", {}) or {}

        cards = ""
        for label, val, color in [
            ("Secrets détectés", len(gitleaks_in), "#ef4444" if len(gitleaks_in) > 0 else "#22c55e"),
            ("CVE Critical", trivy_in.get("critical", "—"), "#ef4444" if trivy_in.get("critical", 0) else "#22c55e"),
            ("CVE High",     trivy_in.get("high", "—"),     "#f97316" if trivy_in.get("high", 0) else "#22c55e"),
            ("CVE Medium",   trivy_in.get("medium", "—"),   "#eab308"),
            ("ZAP High",     zap_in.get("high", "—"),       "#ef4444" if zap_in.get("high", 0) else "#22c55e"),
            ("ZAP Medium",   zap_in.get("medium", "—"),     "#f97316"),
        ]:
            cards += _stat_card(label, val, color)

        input_section = f"""
<div style="margin-bottom:20px">
  <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
    color:var(--text-muted);margin-bottom:14px">Données d'entrée du gate (input.json)</div>
  <div class="stat-grid">{cards}</div>
</div>"""

        raw_json = json.dumps(inp, indent=2, ensure_ascii=False)
        json_section = f"""
<details>
  <summary style="cursor:pointer;font-size:12px;color:var(--text-muted);padding:8px 0;
    border-top:1px solid var(--border)">Voir le JSON complet (input.json)</summary>
  <pre style="background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:8px;
    padding:16px;font-family:var(--mono);font-size:11px;overflow-x:auto;
    color:#94a3b8;margin-top:8px;line-height:1.6">{raw_json}</pre>
</details>"""
    else:
        input_section = '<div class="report-info-bar">Fichier input.json non disponible.</div>'
        json_section  = ""

    return hero + input_section + json_section


def render_sonar(sonar: dict | None) -> str:
    if sonar is None:
        return f"""
<div style="background:rgba(255,255,255,0.03);border:1px dashed rgba(255,255,255,0.12);
  border-radius:10px;padding:40px;text-align:center">
  <div style="font-size:32px;margin-bottom:12px">🔬</div>
  <div style="font-size:14px;color:var(--text-muted);margin-bottom:8px">SonarQube non configuré</div>
  <div style="font-family:var(--mono);font-size:11px;background:rgba(0,0,0,0.3);
    display:inline-block;padding:8px 16px;border-radius:6px;color:#94a3b8">
    python generate_dashboard.py --sonar-url http://host:9000 --sonar-token TOKEN --sonar-project KEY
  </div>
</div>"""

    m = sonar["metrics"]
    gate = sonar["gate_status"]
    gate_color = "#22c55e" if gate == "OK" else "#ef4444"

    rating_map = {"1": "A", "2": "B", "3": "C", "4": "D", "5": "E"}
    def rating(key):
        v = m.get(key, "—")
        return rating_map.get(str(v).split(".")[0], v)

    cards = (
        _stat_card("Quality Gate", "PASSED" if gate == "OK" else gate, gate_color) +
        _stat_card("Bugs", m.get("bugs","—"), "#f97316") +
        _stat_card("Vulnérabilités", m.get("vulnerabilities","—"), "#ef4444") +
        _stat_card("Code Smells", m.get("code_smells","—"), "#eab308") +
        _stat_card("Hotspots", m.get("security_hotspots","—"), "#a855f7") +
        _stat_card("Couverture", f'{m.get("coverage","—")}%', "#3b82f6") +
        _stat_card("Duplication", f'{m.get("duplicated_lines_density","—")}%', "#06b6d4") +
        _stat_card("NCLOC", m.get("ncloc","—"), "#64748b") +
        _stat_card("Fiabilité", rating("reliability_rating"), "#f97316") +
        _stat_card("Sécurité", rating("security_rating"), "#ef4444") +
        _stat_card("Maintenabilité", rating("sqale_rating"), "#eab308")
    )

    conditions_html = ""
    if sonar.get("conditions"):
        cond_rows = ""
        for cond in sonar["conditions"]:
            ok = cond.get("status") == "OK"
            cond_rows += f"""
<tr>
  <td><span style="color:{'#22c55e' if ok else '#ef4444'}">{cond.get("metricKey","")}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px">{cond.get("comparator","")} {cond.get("errorThreshold","")}</span></td>
  <td><span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">{cond.get("actualValue","—")}</span></td>
  <td>{"✅" if ok else "❌"}</td>
</tr>"""
        conditions_html = f"""
<div style="margin-top:24px">
  {_section("⚖️", "Conditions du Quality Gate")}
  <div class="table-wrap">
  <table>
  <thead><tr><th>Métrique</th><th>Seuil</th><th>Valeur actuelle</th><th>Statut</th></tr></thead>
  <tbody>{cond_rows}</tbody>
  </table>
  </div>
</div>"""

    link = f'<a href="{sonar["url"]}" target="_blank" style="display:inline-flex;align-items:center;gap:6px;color:var(--accent);font-size:12px;text-decoration:none;margin-top:16px">→ Ouvrir le dashboard SonarQube</a>'

    return f'<div class="stat-grid">{cards}</div>{link}{conditions_html}'


# ═══════════════════════════════════════════════════════════════════════════════
# CSS / JS / HTML TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');

:root {
  /* DARK THEME (default) */
  --bg:          #0b0f19;
  --surface:     #111827;
  --surface2:    #1a2235;
  --surface3:    #1f2d45;
  --border:      rgba(255,255,255,0.08);
  --border2:     rgba(255,255,255,0.14);
  --text:        #e2e8f0;
  --text-muted:  #64748b;
  --accent:      #60a5fa;
  --mono:        'JetBrains Mono', monospace;
  --sans:        'Plus Jakarta Sans', sans-serif;
  --radius:      8px;
  --radius-lg:   12px;
  --sidebar-w:   230px;
  --nav-h:       56px;
  --shadow:      0 1px 3px rgba(0,0,0,0.5);
}

[data-theme="light"] {
  --bg:         #f1f5f9;
  --surface:    #ffffff;
  --surface2:   #f8fafc;
  --surface3:   #e2e8f0;
  --border:     rgba(0,0,0,0.09);
  --border2:    rgba(0,0,0,0.16);
  --text:       #0f172a;
  --text-muted: #64748b;
  --accent:     #2563eb;
  --shadow:     0 1px 4px rgba(0,0,0,0.1);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  line-height: 1.6;
  display: flex;
  flex-direction: column;
}

/* ─── TOPBAR ─── */
.topbar {
  height: var(--nav-h);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  padding: 0 24px;
  gap: 16px;
  position: sticky;
  top: 0;
  z-index: 100;
  flex-shrink: 0;
}
.topbar-logo {
  font-size: 14px; font-weight: 800; letter-spacing: -0.02em;
  color: var(--text); display: flex; align-items: center; gap: 8px;
}
.topbar-logo span { color: var(--accent); }
.topbar-meta {
  font-size: 11px; color: var(--text-muted); margin-left: 8px;
  display: flex; gap: 16px; flex-wrap: wrap;
}
.topbar-meta b { color: var(--text); }
.topbar-right { margin-left: auto; display: flex; align-items: center; gap: 10px; }

/* theme toggle */
.theme-btn {
  background: var(--surface2); border: 1px solid var(--border2);
  border-radius: 20px; cursor: pointer; padding: 6px 12px;
  font-size: 12px; color: var(--text-muted); font-family: var(--sans);
  transition: all 0.2s; display: flex; align-items: center; gap: 5px;
}
.theme-btn:hover { color: var(--text); background: var(--surface3); }

/* ─── LAYOUT SHELL ─── */
.shell { display: flex; flex: 1; overflow: hidden; }

/* ─── SIDEBAR ─── */
.sidebar {
  width: var(--sidebar-w);
  flex-shrink: 0;
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: 20px 12px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 4px;
  position: sticky;
  top: var(--nav-h);
  height: calc(100vh - var(--nav-h));
}
.nav-label {
  font-size: 10px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--text-muted);
  padding: 0 10px; margin: 12px 0 4px;
}
.nav-label:first-child { margin-top: 0; }
.nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 12px; border-radius: var(--radius);
  font-size: 13px; font-weight: 500; color: var(--text-muted);
  cursor: pointer; border: none; background: none; font-family: var(--sans);
  width: 100%; text-align: left; transition: all 0.15s;
  position: relative;
}
.nav-item:hover { background: var(--surface2); color: var(--text); }
.nav-item.active {
  background: rgba(96,165,250,0.1);
  color: var(--accent);
  font-weight: 700;
}
[data-theme="light"] .nav-item.active { background: rgba(37,99,235,0.08); }
.nav-badge {
  margin-left: auto; font-size: 10px; font-weight: 700; font-family: var(--mono);
  padding: 1px 6px; border-radius: 10px;
}
.nav-badge.red    { background: rgba(239,68,68,0.15);  color: #f87171; }
.nav-badge.orange { background: rgba(249,115,22,0.15); color: #fb923c; }
.nav-badge.blue   { background: rgba(96,165,250,0.15); color: #93c5fd; }
.nav-badge.green  { background: rgba(34,197,94,0.15);  color: #4ade80; }
.nav-badge.gray   { background: rgba(100,116,139,0.15);color: #94a3b8; }

/* ─── MAIN CONTENT ─── */
.content {
  flex: 1;
  overflow-y: auto;
  padding: 32px 36px;
  min-width: 0;
}
.pane { display: none; }
.pane.active { display: block; }

/* ─── STAT GRID ─── */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 12px;
  margin-bottom: 28px;
}
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 16px;
}

/* ─── TABLES ─── */
.table-wrap {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow-x: auto;
  background: var(--surface);
}
table { width: 100%; border-collapse: collapse; font-size: 12px; }
thead th {
  background: var(--surface2);
  color: var(--text-muted);
  text-transform: uppercase;
  font-size: 10px;
  letter-spacing: 0.07em;
  font-weight: 700;
  padding: 10px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
tbody td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  color: var(--text);
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: rgba(255,255,255,0.025); }
[data-theme="light"] tbody tr:hover td { background: rgba(0,0,0,0.025); }

/* ─── FILTER INPUT ─── */
.table-filter-row { margin-bottom: 12px; }
.filter-input {
  background: var(--surface);
  border: 1px solid var(--border2);
  border-radius: var(--radius);
  padding: 8px 14px;
  font-size: 12px;
  color: var(--text);
  font-family: var(--sans);
  width: 320px;
  max-width: 100%;
  outline: none;
  transition: border-color 0.15s;
}
.filter-input:focus { border-color: var(--accent); }
.filter-input::placeholder { color: var(--text-muted); }

/* ─── ALERT CARDS (ZAP) ─── */
.alert-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 20px;
  margin-bottom: 12px;
}

/* ─── INFO BAR ─── */
.report-info-bar {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 16px;
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.report-info-bar strong { color: var(--text); }

/* ─── DETAILS ─── */
details summary { list-style: none; }
details summary::-webkit-details-marker { display: none; }

/* ─── SCROLLBAR ─── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 3px; }
[data-theme="light"] ::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.15); }

/* ─── RESPONSIVE ─── */
@media (max-width: 768px) {
  .sidebar { display: none; }
  .content { padding: 20px 16px; }
}
"""

JS = r"""
function showPane(id) {
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('pane-' + id).classList.add('active');
  document.querySelector('[data-pane="' + id + '"]').classList.add('active');
}

function filterRows(inputId, tbodyId) {
  const q = document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#' + tbodyId + ' tr').forEach(tr => {
    tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
  });
}

function toggleTheme() {
  const root = document.documentElement;
  const isDark = root.getAttribute('data-theme') !== 'light';
  root.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.getElementById('theme-btn-txt').textContent = isDark ? '🌙 Mode sombre' : '☀️ Mode clair';
  localStorage.setItem('dash-theme', isDark ? 'light' : 'dark');
}

window.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('dash-theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
    document.getElementById('theme-btn-txt').textContent = saved === 'light' ? '🌙 Mode sombre' : '☀️ Mode clair';
  }
});
"""


def nav_item(pane_id: str, icon: str, label: str, badge: str = "", badge_cls: str = "gray", active: bool = False) -> str:
    badge_html = f'<span class="nav-badge {badge_cls}">{badge}</span>' if badge else ""
    active_cls = " active" if active else ""
    return (
        f'<button class="nav-item{active_cls}" data-pane="{pane_id}" onclick="showPane(\'{pane_id}\')">'
        f'{icon} {label}{badge_html}</button>'
    )


def build_html(
    gitleaks, trivy, zap, sbom, opa, falco,
    sonar=None,
    project_name: str = "archivage-Doc",
    generated_at: str = "",
) -> str:
    now_str = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    gl_cls = "red" if gitleaks["count"] > 0 else "green"
    tv_cls = "red" if trivy["counts"].get("CRITICAL",0) > 0 else ("orange" if trivy["counts"].get("HIGH",0) > 0 else "green")
    zp_cls = "red" if zap["counts"].get("HIGH",0) > 0 else ("orange" if zap["counts"].get("MEDIUM",0) > 0 else "green")
    fc_cls = "red" if falco["count"] > 0 else "green"

    sidebar = f"""
<aside class="sidebar">
  <div class="nav-label">Rapport</div>
  {nav_item("overview",  "📋", "Vue d'ensemble", active=True)}
  <div class="nav-label">Sécurité</div>
  {nav_item("gitleaks",  "🔑", "Gitleaks",   str(gitleaks["count"]), gl_cls)}
  {nav_item("trivy",     "🛡️", "Trivy SCA",   str(trivy["total"]),   tv_cls)}
  {nav_item("zap",       "🌐", "OWASP ZAP",   str(zap["total"]),     zp_cls)}
  {nav_item("falco",     "⚡", "Falco Runtime", str(falco["count"]), fc_cls)}
  <div class="nav-label">Artefacts</div>
  {nav_item("sbom",      "📦", "SBOM",        str(sbom["total"]),    "blue")}
  {nav_item("opa",       "⚖️", "OPA Gate",    "PASS" if opa["passed"] else ("FAIL" if opa["passed"] is False else "N/A"), "green" if opa["passed"] else "red")}
  {nav_item("sonar",     "🔬", "SonarQube",   sonar["metrics"].get("alert_status","") if sonar else "—", "green" if (sonar and sonar.get("gate_status") == "OK") else "gray")}
</aside>"""

    def pane(pid, title, icon, content, active=False):
        hdr = _section(icon, title)
        active_cls = " active" if active else ""
        return f'<div id="pane-{pid}" class="pane{active_cls}"><div style="max-width:1100px">{hdr}{content}</div></div>'

    content_panes = (
        pane("overview",  "Vue d'ensemble", "📋", render_overview(gitleaks, trivy, zap, sbom, opa, falco), active=True) +
        pane("gitleaks",  "Gitleaks — Secrets détectés", "🔑", render_gitleaks(gitleaks)) +
        pane("trivy",     "Trivy — Vulnérabilités SCA/FS", "🛡️", render_trivy(trivy)) +
        pane("zap",       "OWASP ZAP — Alertes DAST", "🌐", render_zap(zap)) +
        pane("falco",     "Falco — Runtime Security", "⚡", render_falco(falco)) +
        pane("sbom",      "SBOM — Inventaire CycloneDX", "📦", render_sbom(sbom)) +
        pane("opa",       "OPA Security Gate", "⚖️", render_opa(opa)) +
        pane("sonar",     "SonarQube — Qualité du code", "🔬", render_sonar(sonar))
    )

    return f"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevSecOps Dashboard — {project_name}</title>
  <style>{CSS}</style>
</head>
<body>

<header class="topbar">
  <div class="topbar-logo">
    <span>🔐</span> DevSecOps <span>Dashboard</span>
  </div>
  <div class="topbar-meta">
    <span>Projet&nbsp;: <b>{project_name}</b></span>
    <span>Généré&nbsp;: <b>{now_str}</b></span>
  </div>
  <div class="topbar-right">
    <button class="theme-btn" onclick="toggleTheme()">
      <span id="theme-btn-txt">☀️ Mode clair</span>
    </button>
  </div>
</header>

<div class="shell">
  {sidebar}
  <main class="content">
    {content_panes}
  </main>
</div>

<script>{JS}</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Génère un dashboard HTML de sécurité DevSecOps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--reports",       default="reports")
    parser.add_argument("--output",        default="security-dashboard.html")
    parser.add_argument("--project",       default="archivage-Doc")
    parser.add_argument("--sonar-url",     default="")
    parser.add_argument("--sonar-token",   default="")
    parser.add_argument("--sonar-project", default="")
    parser.add_argument("--serve",         action="store_true")
    args = parser.parse_args()

    reports_dir = Path(args.reports)
    output_path = Path(args.output)

    print(f"\n{'='*60}")
    print(f"  DevSecOps Dashboard Generator (Enhanced)")
    print(f"{'='*60}")
    print(f"  Dossier rapports : {reports_dir.resolve()}")
    print(f"  Sortie           : {output_path.resolve()}")
    print()

    print("  [1/7] Gitleaks…")
    gitleaks = parse_gitleaks(reports_dir)
    print(f"        {gitleaks['count']} secret(s)")

    print("  [2/7] Trivy…")
    trivy = parse_trivy(reports_dir)
    print(f"        {trivy['total']} CVE(s) — CRITICAL:{trivy['counts'].get('CRITICAL',0)} HIGH:{trivy['counts'].get('HIGH',0)}")

    print("  [3/7] OWASP ZAP…")
    zap = parse_zap(reports_dir)
    print(f"        {zap['total']} alerte(s) — HIGH:{zap['counts'].get('HIGH',0)}")

    print("  [4/7] Falco Runtime…")
    falco = parse_falco(reports_dir)
    print(
        f"        {falco['count']} événement(s) — "
        f"{falco.get('unique_count', falco['count'])} signature(s) unique(s)"
    )

    print("  [5/7] SBOM CycloneDX…")
    sbom = parse_sbom(reports_dir)
    print(f"        {sbom['total']} composant(s)")

    print("  [6/7] OPA Gate…")
    opa = parse_opa(reports_dir)
    print(f"        Gate : {'PASS' if opa['passed'] else ('FAIL' if opa['passed'] is False else 'N/A')}")

    sonar = None
    print("  [7/7] SonarQube…")
    if args.sonar_url and args.sonar_project:
        sonar = fetch_sonarqube(args.sonar_url, args.sonar_token, args.sonar_project)
        print(f"        Gate : {sonar['gate_status'] if sonar else 'inaccessible'}")
    else:
        print("        Non configuré")

    print()
    print("  Génération du HTML…")
    html = build_html(
        gitleaks=gitleaks, trivy=trivy, zap=zap, sbom=sbom, opa=opa, falco=falco,
        sonar=sonar, project_name=args.project,
    )
    output_path.write_text(html, encoding="utf-8")
    print(f"  ✅ Dashboard généré : {output_path.resolve()}")
    print(f"     Taille           : {output_path.stat().st_size // 1024} Ko")

    if args.serve:
        port = 8765
        os.chdir(output_path.parent)
        handler = http.server.SimpleHTTPRequestHandler
        handler.log_message = lambda *a: None
        server = http.server.HTTPServer(("", port), handler)
        url = f"http://localhost:{port}/{output_path.name}"
        print(f"\n  🌐 Serveur démarré sur {url}\n     Ctrl+C pour arrêter.\n")
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Serveur arrêté.")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
