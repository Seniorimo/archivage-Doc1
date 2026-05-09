#!/usr/bin/env python3
"""
generate_dashboard.py
─────────────────────
Génère un dashboard HTML complet à partir des rapports de sécurité
produits par le pipeline DevSecOps (Jenkins / GitHub Actions).

Briques couvertes :
  • Gitleaks   — secrets détectés (gitleaks-report.json)
  • Trivy      — vulnérabilités SCA/FS  (trivy-report.json)
  • OWASP ZAP  — alertes DAST          (zap-report.json)
  • CycloneDX  — inventaire SBOM       (bom.json)
  • OPA        — résultat security gate (opa-result.txt + input.json)
  • SonarQube  — qualité code          (API REST optionnelle)

Usage :
  python generate_dashboard.py                         # chemins par défaut
  python generate_dashboard.py --reports ./my-reports  # dossier custom
  python generate_dashboard.py --reports ./r --sonar-url http://localhost:9000 \
         --sonar-token squ_xxx --sonar-project archivage-Doc
  python generate_dashboard.py --serve                 # ouvre le navigateur auto
"""

import argparse
import json
import os
import sys
import webbrowser
import http.server
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError


# ═══════════════════════════════════════════════════════════════════════════════
# PARSERS — un par brique de sécurité
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
        })
    return {"count": len(findings), "findings": findings}


def parse_trivy(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "trivy" / "trivy-report.json", {"Results": []})
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulns = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            vulns.append({
                "id":          v.get("VulnerabilityID", "?"),
                "pkg":         v.get("PkgName", "?"),
                "installed":   v.get("InstalledVersion", "?"),
                "fixed":       v.get("FixedVersion", "—"),
                "severity":    sev,
                "title":       (v.get("Title") or v.get("Description") or "")[:120],
                "target":      target,
            })
    # trier par sévérité
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda x: order.get(x["severity"], 9))
    return {"counts": sev_counts, "total": sum(sev_counts.values()), "vulns": vulns}


def parse_zap(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "zap" / "zap-report.json",
                     {"site": [{"alerts": []}]})
    risk_map = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    alerts = []
    target = ""
    for site in data.get("site", []) or []:
        if not target:
            target = site.get("@name", site.get("name", ""))
        for a in site.get("alerts", []) or []:
            rc = int(a.get("riskcode", 0))
            label = risk_map.get(rc, "INFO")
            counts[label] = counts.get(label, 0) + 1
            url = ""
            for inst in (a.get("instances") or [])[:1]:
                url = inst.get("uri", "")
            alerts.append({
                "name":     a.get("alert", a.get("name", "?")),
                "risk":     label,
                "riskcode": rc,
                "url":      url,
                "desc":     (a.get("desc") or "")[:200],
                "solution": (a.get("solution") or "")[:200],
                "count":    int(a.get("count", 1)),
            })
    alerts.sort(key=lambda x: -x["riskcode"])
    return {"target": target, "counts": counts, "total": sum(counts.values()), "alerts": alerts}


def parse_sbom(reports_dir: Path) -> dict:
    data = load_json(reports_dir / "sbom" / "bom.json", {})
    components = data.get("components", []) or []
    by_type: dict = {}
    for c in components:
        t = c.get("type", "library")
        by_type[t] = by_type.get(t, 0) + 1
    comp_list = []
    for c in components[:200]:  # limiter l'affichage à 200
        comp_list.append({
            "name":    c.get("name", "?"),
            "version": c.get("version", "—"),
            "type":    c.get("type", "library"),
            "purl":    c.get("purl", ""),
        })
    return {
        "total":      len(components),
        "by_type":    by_type,
        "components": comp_list,
        "spec_version": data.get("specVersion", "—"),
        "serial":     data.get("serialNumber", "—"),
    }


def parse_opa(reports_dir: Path) -> dict:
    result_file = reports_dir / "opa" / "opa-result.txt"
    input_file  = reports_dir / "opa" / "input.json"
    passed = None
    if result_file.exists():
        content = result_file.read_text(encoding="utf-8").strip()
        if content == "true":
            passed = True
        elif content == "false":
            passed = False
    opa_input = load_json(input_file, {})
    return {"passed": passed, "input": opa_input}


def fetch_sonarqube(sonar_url: str, sonar_token: str, project_key: str) -> dict | None:
    """Appel API SonarQube — retourne None si inaccessible."""
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
            "duplicated_lines_density,ncloc,security_hotspots,alert_status"
        )
        metrics = {}
        for m in measures_resp.get("component", {}).get("measures", []):
            metrics[m["metric"]] = m.get("value", "—")

        gate_resp = api_get(f"/api/qualitygates/project_status?projectKey={project_key}")
        gate = gate_resp.get("projectStatus", {})

        return {
            "metrics": metrics,
            "gate_status": gate.get("status", "NONE"),
            "conditions": gate.get("conditions", []),
            "url": f"{sonar_url.rstrip('/')}/dashboard?id={project_key}",
        }
    except (URLError, Exception) as e:
        print(f"  [WARN] SonarQube inaccessible : {e}", file=sys.stderr)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATEUR HTML
# ═══════════════════════════════════════════════════════════════════════════════

def severity_color_css(sev: str) -> str:
    return {
        "CRITICAL": "#e53935", "HIGH": "#f4511e",
        "MEDIUM":   "#fb8c00", "LOW":  "#43a047",
        "UNKNOWN":  "#78909c", "INFO": "#1e88e5",
    }.get(sev.upper(), "#78909c")


def risk_color_css(risk: str) -> str:
    return {
        "HIGH": "#e53935", "MEDIUM": "#fb8c00",
        "LOW":  "#43a047", "INFO":   "#1e88e5",
    }.get(risk.upper(), "#78909c")


def badge(label: str, count, color: str) -> str:
    return (
        f'<span class="badge" style="background:{color}">'
        f'<span class="badge-num">{count}</span>'
        f'<span class="badge-lbl">{label}</span></span>'
    )


def status_chip(ok: bool | None) -> str:
    if ok is True:
        return '<span class="chip chip-pass">✓ PASS</span>'
    if ok is False:
        return '<span class="chip chip-fail">✗ FAIL</span>'
    return '<span class="chip chip-unknown">? N/A</span>'


def section_header(icon: str, title: str, extra: str = "") -> str:
    return f"""
    <div class="section-header">
      <span class="section-icon">{icon}</span>
      <h2>{title}</h2>
      {f'<span class="section-extra">{extra}</span>' if extra else ''}
    </div>"""


def vuln_table_rows_trivy(vulns: list) -> str:
    if not vulns:
        return '<tr><td colspan="6" class="empty-row">Aucune vulnérabilité détectée</td></tr>'
    rows = []
    for v in vulns:
        c = severity_color_css(v["severity"])
        rows.append(
            f'<tr>'
            f'<td><span class="sev-badge" style="background:{c}">{v["severity"]}</span></td>'
            f'<td class="mono">{v["id"]}</td>'
            f'<td>{v["pkg"]}</td>'
            f'<td class="mono">{v["installed"]}</td>'
            f'<td class="mono fix-version">{v["fixed"]}</td>'
            f'<td class="desc-cell">{v["title"]}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def alert_table_rows_zap(alerts: list) -> str:
    if not alerts:
        return '<tr><td colspan="4" class="empty-row">Aucune alerte détectée</td></tr>'
    rows = []
    for a in alerts:
        c = risk_color_css(a["risk"])
        url_str = f'<br><small class="url-cell">{a["url"]}</small>' if a["url"] else ""
        rows.append(
            f'<tr>'
            f'<td><span class="sev-badge" style="background:{c}">{a["risk"]}</span></td>'
            f'<td>{a["name"]}{url_str}</td>'
            f'<td class="desc-cell">{a["desc"]}</td>'
            f'<td class="desc-cell">{a["solution"]}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def gitleaks_table_rows(findings: list) -> str:
    if not findings:
        return '<tr><td colspan="5" class="empty-row">Aucun secret détecté ✓</td></tr>'
    rows = []
    for f in findings:
        rows.append(
            f'<tr>'
            f'<td><span class="sev-badge" style="background:#e53935">SECRET</span></td>'
            f'<td class="mono">{f["rule"]}</td>'
            f'<td class="mono">{f["file"]}:{f["line"]}</td>'
            f'<td class="mono">{f["commit"]}</td>'
            f'<td class="mono secret-cell">{f["secret"]}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def sbom_table_rows(components: list) -> str:
    if not components:
        return '<tr><td colspan="3" class="empty-row">Aucun composant</td></tr>'
    rows = []
    for c in components:
        purl = f'<br><small class="mono url-cell">{c["purl"]}</small>' if c["purl"] else ""
        rows.append(
            f'<tr>'
            f'<td>{c["name"]}{purl}</td>'
            f'<td class="mono">{c["version"]}</td>'
            f'<td><span class="type-tag">{c["type"]}</span></td>'
            f'</tr>'
        )
    return "\n".join(rows)


def sonar_metrics_html(sonar: dict) -> str:
    m = sonar["metrics"]
    gate = sonar["gate_status"]
    gate_color = "#43a047" if gate == "OK" else "#e53935"
    gate_label = "PASSED" if gate == "OK" else gate

    def metric_card(label, value, unit="", color="#e0e6f0"):
        return (
            f'<div class="metric-card" style="border-top:3px solid {color}">'
            f'<div class="metric-val">{value}<span class="metric-unit">{unit}</span></div>'
            f'<div class="metric-lbl">{label}</div></div>'
        )

    cards = [
        metric_card("Quality Gate", gate_label, color=gate_color),
        metric_card("Bugs",         m.get("bugs", "—"),                  color="#f4511e"),
        metric_card("Vulnérabilités", m.get("vulnerabilities", "—"),      color="#e53935"),
        metric_card("Code Smells",  m.get("code_smells", "—"),           color="#fb8c00"),
        metric_card("Hotspots",     m.get("security_hotspots", "—"),     color="#8e24aa"),
        metric_card("Couverture",   m.get("coverage", "—"),     "%",     color="#1e88e5"),
        metric_card("Duplication",  m.get("duplicated_lines_density", "—"), "%", color="#00897b"),
        metric_card("Lignes code",  m.get("ncloc", "—"),                 color="#546e7a"),
    ]
    link = f'<a class="sonar-link" href="{sonar["url"]}" target="_blank">→ Ouvrir SonarQube</a>'
    return f'<div class="metric-grid">{"".join(cards)}</div>{link}'


def build_summary_bar(gitleaks, trivy, zap, opa) -> str:
    """Barre de synthèse globale en haut du dashboard."""
    opa_ok = opa["passed"]
    overall_color = "#43a047"
    overall_label = "SECURE"
    if opa_ok is False or gitleaks["count"] > 0 or trivy["counts"].get("CRITICAL", 0) > 0:
        overall_color = "#e53935"
        overall_label = "AT RISK"
    elif trivy["counts"].get("HIGH", 0) > 0 or zap["counts"].get("HIGH", 0) > 0:
        overall_color = "#fb8c00"
        overall_label = "WARNING"

    return f"""
    <div class="summary-bar">
      <div class="overall-status" style="border-color:{overall_color};color:{overall_color}">
        {overall_label}
      </div>
      <div class="summary-items">
        <div class="summary-item">
          <span class="sum-icon">🔑</span>
          <span class="sum-label">Secrets</span>
          <span class="sum-val {'sum-bad' if gitleaks['count'] > 0 else 'sum-ok'}">{gitleaks['count']}</span>
        </div>
        <div class="summary-item">
          <span class="sum-icon">🛡</span>
          <span class="sum-label">CVE Critical</span>
          <span class="sum-val {'sum-bad' if trivy['counts'].get('CRITICAL',0) > 0 else 'sum-ok'}">{trivy['counts'].get('CRITICAL', 0)}</span>
        </div>
        <div class="summary-item">
          <span class="sum-icon">🛡</span>
          <span class="sum-label">CVE High</span>
          <span class="sum-val {'sum-warn' if trivy['counts'].get('HIGH',0) > 0 else 'sum-ok'}">{trivy['counts'].get('HIGH', 0)}</span>
        </div>
        <div class="summary-item">
          <span class="sum-icon">🌐</span>
          <span class="sum-label">ZAP High</span>
          <span class="sum-val {'sum-bad' if zap['counts'].get('HIGH',0) > 0 else 'sum-ok'}">{zap['counts'].get('HIGH', 0)}</span>
        </div>
        <div class="summary-item">
          <span class="sum-icon">⚖</span>
          <span class="sum-label">OPA Gate</span>
          <span class="sum-val {'sum-ok' if opa_ok else ('sum-bad' if opa_ok is False else 'sum-neutral')}">{
            'PASS' if opa_ok else ('FAIL' if opa_ok is False else 'N/A')
          }</span>
        </div>
      </div>
    </div>"""


# ═══════════════════════════════════════════════════════════════════════════════
# CSS + HTML TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

CSS = """
:root {
  --bg:        #0d1117;
  --surface:   #161b22;
  --surface2:  #1c2230;
  --border:    #30363d;
  --text:      #c9d1d9;
  --text-dim:  #8b949e;
  --accent:    #58a6ff;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --font-ui:   'Sora', 'DM Sans', 'Segoe UI', sans-serif;
  --radius:    8px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  line-height: 1.6;
}

/* ── HEADER ── */
.header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1b2e 100%);
  border-bottom: 1px solid var(--border);
  padding: 32px 40px 24px;
  position: relative;
  overflow: hidden;
}
.header::before {
  content: '';
  position: absolute; inset: 0;
  background: radial-gradient(ellipse at 70% 50%, rgba(88,166,255,.06) 0%, transparent 60%);
  pointer-events: none;
}
.header-top { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
.header h1  { font-size: 1.8rem; font-weight: 700; letter-spacing: -.02em; color: #fff; }
.header h1 span { color: var(--accent); }
.header-meta { font-size: .78rem; color: var(--text-dim); margin-top: 6px; display: flex; gap: 20px; flex-wrap: wrap; }
.header-meta b { color: var(--text); }

/* ── SUMMARY BAR ── */
.summary-bar {
  margin: 28px 40px 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 28px;
  display: flex;
  align-items: center;
  gap: 32px;
  flex-wrap: wrap;
}
.overall-status {
  font-size: 1.1rem;
  font-weight: 800;
  letter-spacing: .08em;
  border: 2px solid;
  border-radius: 6px;
  padding: 8px 20px;
  min-width: 120px;
  text-align: center;
}
.summary-items { display: flex; gap: 24px; flex-wrap: wrap; }
.summary-item  { display: flex; flex-direction: column; align-items: center; gap: 2px; min-width: 70px; }
.sum-icon  { font-size: 1.2rem; }
.sum-label { font-size: .68rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: .06em; }
.sum-val   { font-size: 1.3rem; font-weight: 700; font-family: var(--font-mono); }
.sum-ok      { color: #43a047; }
.sum-bad     { color: #e53935; }
.sum-warn    { color: #fb8c00; }
.sum-neutral { color: var(--text-dim); }

/* ── NAV TABS ── */
.nav { display: flex; gap: 4px; padding: 24px 40px 0; border-bottom: 1px solid var(--border); overflow-x: auto; }
.tab-btn {
  background: none; border: none; cursor: pointer;
  color: var(--text-dim); font-family: var(--font-ui); font-size: .85rem;
  padding: 10px 18px; border-radius: var(--radius) var(--radius) 0 0;
  border: 1px solid transparent; border-bottom: none;
  transition: all .15s; white-space: nowrap;
  position: relative; bottom: -1px;
}
.tab-btn:hover { color: var(--text); background: var(--surface); }
.tab-btn.active {
  color: var(--accent); background: var(--surface);
  border-color: var(--border); border-bottom-color: var(--surface);
  font-weight: 600;
}

/* ── MAIN CONTENT ── */
.main    { padding: 32px 40px; }
.tab-pane { display: none; }
.tab-pane.active { display: block; }

/* ── SECTION ── */
.section        { margin-bottom: 36px; }
.section-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
.section-icon   { font-size: 1.3rem; }
.section-header h2  { font-size: 1rem; font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: .06em; }
.section-extra  { margin-left: auto; font-size: .78rem; color: var(--text-dim); }

/* ── BADGES ── */
.badge-row  { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
.badge {
  display: inline-flex; flex-direction: column; align-items: center;
  border-radius: 8px; padding: 12px 20px; min-width: 80px;
  color: #fff; font-family: var(--font-mono);
}
.badge-num { font-size: 1.8rem; font-weight: 700; line-height: 1; }
.badge-lbl { font-size: .68rem; text-transform: uppercase; letter-spacing: .06em; margin-top: 2px; opacity: .85; }

/* ── CHIPS ── */
.chip { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: .78rem; font-weight: 700; letter-spacing: .04em; }
.chip-pass    { background: rgba(67,160,71,.2); color: #66bb6a; border: 1px solid #43a047; }
.chip-fail    { background: rgba(229,57,53,.2);  color: #ef5350; border: 1px solid #e53935; }
.chip-unknown { background: rgba(120,144,156,.2);color: #90a4ae; border: 1px solid #546e7a; }

/* ── TABLES ── */
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
}
table { width: 100%; border-collapse: collapse; font-size: .83rem; }
thead th {
  background: var(--surface2);
  color: var(--text-dim); text-transform: uppercase;
  letter-spacing: .05em; font-size: .72rem;
  padding: 10px 14px; text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
tbody td {
  padding: 9px 14px;
  border-bottom: 1px solid rgba(48,54,61,.6);
  vertical-align: top;
  color: var(--text);
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: rgba(255,255,255,.03); }
.empty-row { text-align: center; padding: 28px !important; color: var(--text-dim); font-style: italic; }

/* ── SPECIFIC CELLS ── */
.mono        { font-family: var(--font-mono); font-size: .78rem; }
.desc-cell   { max-width: 320px; font-size: .78rem; color: var(--text-dim); }
.url-cell    { color: var(--text-dim); word-break: break-all; }
.fix-version { color: #43a047; }
.secret-cell { color: #ef9a9a; letter-spacing: .05em; }
.sev-badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: .72rem; font-weight: 700; color: #fff;
  font-family: var(--font-mono); white-space: nowrap;
}
.type-tag {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: .72rem; background: var(--surface2); color: var(--text-dim);
  border: 1px solid var(--border); font-family: var(--font-mono);
}

/* ── METRIC CARDS (SonarQube) ── */
.metric-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 14px; margin-bottom: 16px; }
.metric-card {
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 16px 18px;
}
.metric-val  { font-size: 1.6rem; font-weight: 700; font-family: var(--font-mono); color: #fff; }
.metric-unit { font-size: .9rem; color: var(--text-dim); margin-left: 2px; }
.metric-lbl  { font-size: .72rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
.sonar-link  { display: inline-block; color: var(--accent); font-size: .83rem; text-decoration: none; margin-top: 4px; }
.sonar-link:hover { text-decoration: underline; }

/* ── OPA DETAIL ── */
.opa-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 14px; margin-top: 16px; }
.opa-card { background: var(--surface2); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 18px; }
.opa-card-title { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim); margin-bottom: 6px; }
.opa-card-val   { font-size: 1.4rem; font-weight: 700; font-family: var(--font-mono); color: #fff; }

/* ── SBOM STATS ── */
.sbom-stats { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 20px; }
.sbom-stat  { background: var(--surface2); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 20px; }
.sbom-stat .num { font-size: 1.4rem; font-weight: 700; font-family: var(--font-mono); color: #fff; }
.sbom-stat .lbl { font-size: .72rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: .05em; }

/* ── INFO BOX ── */
.info-box {
  background: rgba(88,166,255,.07); border: 1px solid rgba(88,166,255,.2);
  border-radius: var(--radius); padding: 14px 18px;
  font-size: .82rem; color: var(--text-dim); margin-bottom: 20px;
}
.info-box b { color: var(--accent); }

/* ── FOOTER ── */
.footer { border-top: 1px solid var(--border); padding: 20px 40px; text-align: center; font-size: .75rem; color: var(--text-dim); }

/* ── RESPONSIVE ── */
@media (max-width: 700px) {
  .header, .nav, .main { padding-left: 16px; padding-right: 16px; }
  .summary-bar { margin-left: 16px; margin-right: 16px; }
  .header h1 { font-size: 1.3rem; }
}
"""

JS = """
function showTab(id) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelector('[data-tab="' + id + '"]').classList.add('active');
  document.getElementById('pane-' + id).classList.add('active');
}
// filtre tableau trivy
function filterTable(inputId, tableId) {
  const q = document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(tr => {
    tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
  });
}
"""


def build_html(
    gitleaks, trivy, zap, sbom, opa,
    sonar=None,
    project_name: str = "archivage-Doc",
    generated_at: str = "",
) -> str:

    now_str = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── TAB : OVERVIEW ──────────────────────────────────────────────────────
    opa_input = opa.get("input", {})
    opa_trivy  = opa_input.get("trivy", {})
    opa_gitleaks_count = len(opa_input.get("gitleaks", []))
    opa_zap    = opa_input.get("zap", {})

    pane_overview = f"""
    {build_summary_bar(gitleaks, trivy, zap, opa)}
    <div class="main" style="padding-top:28px">
      <div class="section">
        {section_header("⚖️", "OPA Security Gate", status_chip(opa["passed"]))}
        <div class="opa-grid">
          <div class="opa-card"><div class="opa-card-title">Gate résultat</div>
            <div class="opa-card-val">{'PASS ✓' if opa['passed'] else ('FAIL ✗' if opa['passed'] is False else 'N/A')}</div></div>
          <div class="opa-card"><div class="opa-card-title">Secrets (Gitleaks)</div>
            <div class="opa-card-val" style="color:{'#e53935' if opa_gitleaks_count > 0 else '#43a047'}">{opa_gitleaks_count}</div></div>
          <div class="opa-card"><div class="opa-card-title">CVE Critical (Trivy)</div>
            <div class="opa-card-val" style="color:{'#e53935' if opa_trivy.get('critical',0) > 0 else '#43a047'}">{opa_trivy.get('critical', '—')}</div></div>
          <div class="opa-card"><div class="opa-card-title">CVE High (Trivy)</div>
            <div class="opa-card-val" style="color:{'#fb8c00' if opa_trivy.get('high',0) > 0 else '#43a047'}">{opa_trivy.get('high', '—')}</div></div>
          <div class="opa-card"><div class="opa-card-title">ZAP High</div>
            <div class="opa-card-val" style="color:{'#e53935' if opa_zap.get('high',0) > 0 else '#43a047'}">{opa_zap.get('high', '—')}</div></div>
        </div>
      </div>

      <div class="section">
        {section_header("📊", "Synthèse par brique")}
        <div class="badge-row">
          {badge("Secrets", gitleaks['count'], '#e53935' if gitleaks['count'] > 0 else '#2e7d32')}
          {badge("CVE Critical", trivy['counts'].get('CRITICAL', 0), '#e53935' if trivy['counts'].get('CRITICAL',0) > 0 else '#2e7d32')}
          {badge("CVE High", trivy['counts'].get('HIGH', 0), '#f4511e' if trivy['counts'].get('HIGH',0) > 0 else '#2e7d32')}
          {badge("CVE Medium", trivy['counts'].get('MEDIUM', 0), '#fb8c00')}
          {badge("CVE Low", trivy['counts'].get('LOW', 0), '#546e7a')}
          {badge("ZAP High", zap['counts'].get('HIGH', 0), '#e53935' if zap['counts'].get('HIGH',0) > 0 else '#2e7d32')}
          {badge("ZAP Medium", zap['counts'].get('MEDIUM', 0), '#fb8c00')}
          {badge("ZAP Low", zap['counts'].get('LOW', 0), '#546e7a')}
          {badge("Composants", sbom['total'], '#1565c0')}
        </div>
      </div>
    </div>"""

    # ── TAB : GITLEAKS ───────────────────────────────────────────────────────
    pane_gitleaks = f"""
    <div class="main">
      <div class="section">
        {section_header("🔑", "Secrets détectés — Gitleaks", f"{gitleaks['count']} finding(s)")}
        {'<div class="info-box">✅ Aucun secret détecté dans le code source.</div>' if not gitleaks['findings'] else ''}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Sévérité</th><th>Règle</th><th>Fichier:Ligne</th><th>Commit</th><th>Secret (masqué)</th></tr></thead>
            <tbody>{gitleaks_table_rows(gitleaks['findings'])}</tbody>
          </table>
        </div>
      </div>
    </div>"""

    # ── TAB : TRIVY ──────────────────────────────────────────────────────────
    pane_trivy = f"""
    <div class="main">
      <div class="section">
        {section_header("🛡️", "Vulnérabilités SCA/FS — Trivy", f"{trivy['total']} vulnérabilité(s)")}
        <div class="badge-row">
          {badge("CRITICAL", trivy['counts'].get('CRITICAL', 0), '#e53935')}
          {badge("HIGH",     trivy['counts'].get('HIGH', 0),     '#f4511e')}
          {badge("MEDIUM",   trivy['counts'].get('MEDIUM', 0),   '#fb8c00')}
          {badge("LOW",      trivy['counts'].get('LOW', 0),      '#43a047')}
          {badge("UNKNOWN",  trivy['counts'].get('UNKNOWN', 0),  '#78909c')}
        </div>
        <div style="margin-bottom:12px">
          <input id="trivy-filter" type="text" placeholder="🔍 Filtrer par CVE, package, sévérité…"
            oninput="filterTable('trivy-filter','trivy-table')"
            style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;
                   padding:8px 14px;color:var(--text);font-family:var(--font-ui);font-size:.83rem;width:320px">
        </div>
        <div class="table-wrap">
          <table id="trivy-table">
            <thead><tr><th>Sév.</th><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Description</th></tr></thead>
            <tbody>{vuln_table_rows_trivy(trivy['vulns'])}</tbody>
          </table>
        </div>
      </div>
    </div>"""

    # ── TAB : ZAP ────────────────────────────────────────────────────────────
    target_str = f'Cible : <b>{zap["target"]}</b>' if zap["target"] else ""
    pane_zap = f"""
    <div class="main">
      <div class="section">
        {section_header("🌐", "Alertes DAST — OWASP ZAP", f"{zap['total']} alerte(s)")}
        {f'<div class="info-box">{target_str}</div>' if target_str else ''}
        <div class="badge-row">
          {badge("HIGH",   zap['counts'].get('HIGH', 0),   '#e53935')}
          {badge("MEDIUM", zap['counts'].get('MEDIUM', 0), '#fb8c00')}
          {badge("LOW",    zap['counts'].get('LOW', 0),    '#43a047')}
          {badge("INFO",   zap['counts'].get('INFO', 0),   '#1e88e5')}
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Risque</th><th>Alerte / URL</th><th>Description</th><th>Solution</th></tr></thead>
            <tbody>{alert_table_rows_zap(zap['alerts'])}</tbody>
          </table>
        </div>
      </div>
    </div>"""

    # ── TAB : SBOM ───────────────────────────────────────────────────────────
    sbom_type_badges = " ".join(
        badge(t, c, '#1565c0') for t, c in sbom['by_type'].items()
    )
    pane_sbom = f"""
    <div class="main">
      <div class="section">
        {section_header("📦", "SBOM — CycloneDX", f"{sbom['total']} composant(s)")}
        <div class="info-box">
          <b>Spec :</b> CycloneDX {sbom['spec_version']} &nbsp;|&nbsp;
          <b>Serial :</b> <span style="font-family:var(--font-mono);font-size:.75rem">{sbom['serial'][:40] or '—'}</span>
        </div>
        <div class="badge-row">{sbom_type_badges}</div>
        <div style="margin-bottom:12px">
          <input id="sbom-filter" type="text" placeholder="🔍 Filtrer par nom, version…"
            oninput="filterTable('sbom-filter','sbom-table')"
            style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;
                   padding:8px 14px;color:var(--text);font-family:var(--font-ui);font-size:.83rem;width:320px">
        </div>
        {'<div class="info-box" style="color:#8b949e;font-style:italic">Affichage limité aux 200 premiers composants.</div>' if sbom['total'] > 200 else ''}
        <div class="table-wrap">
          <table id="sbom-table">
            <thead><tr><th>Composant / PURL</th><th>Version</th><th>Type</th></tr></thead>
            <tbody>{sbom_table_rows(sbom['components'])}</tbody>
          </table>
        </div>
      </div>
    </div>"""

    # ── TAB : SONARQUBE ──────────────────────────────────────────────────────
    if sonar:
        pane_sonar = f"""
        <div class="main">
          <div class="section">
            {section_header("🔬", "Qualité Code — SonarQube")}
            {sonar_metrics_html(sonar)}
          </div>
        </div>"""
        sonar_tab = '<button class="tab-btn" data-tab="sonar" onclick="showTab(\'sonar\')">🔬 SonarQube</button>'
        sonar_pane = f'<div id="pane-sonar" class="tab-pane">{pane_sonar}</div>'
    else:
        sonar_tab = '<button class="tab-btn" data-tab="sonar" onclick="showTab(\'sonar\')">🔬 SonarQube <small style="opacity:.5">(non configuré)</small></button>'
        sonar_pane = '<div id="pane-sonar" class="tab-pane"><div class="main"><div class="info-box">SonarQube non configuré. Relancez avec <code>--sonar-url</code>, <code>--sonar-token</code> et <code>--sonar-project</code>.</div></div></div>'

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevSecOps Dashboard — {project_name}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>{CSS}</style>
</head>
<body>

<header class="header">
  <div class="header-top">
    <div>
      <h1>DevSecOps <span>Security Dashboard</span></h1>
      <div class="header-meta">
        <span>🗂 Projet : <b>{project_name}</b></span>
        <span>🕒 Généré le : <b>{now_str}</b></span>
      </div>
    </div>
  </div>
</header>

<nav class="nav">
  <button class="tab-btn active" data-tab="overview" onclick="showTab('overview')">📋 Vue d'ensemble</button>
  <button class="tab-btn" data-tab="gitleaks" onclick="showTab('gitleaks')">🔑 Gitleaks <span style="background:#e53935;color:#fff;border-radius:10px;padding:1px 7px;font-size:.72rem;margin-left:4px">{gitleaks['count']}</span></button>
  <button class="tab-btn" data-tab="trivy"    onclick="showTab('trivy')">🛡 Trivy <span style="background:#f4511e;color:#fff;border-radius:10px;padding:1px 7px;font-size:.72rem;margin-left:4px">{trivy['total']}</span></button>
  <button class="tab-btn" data-tab="zap"      onclick="showTab('zap')">🌐 ZAP <span style="background:#fb8c00;color:#fff;border-radius:10px;padding:1px 7px;font-size:.72rem;margin-left:4px">{zap['total']}</span></button>
  <button class="tab-btn" data-tab="sbom"     onclick="showTab('sbom')">📦 SBOM <span style="background:#1565c0;color:#fff;border-radius:10px;padding:1px 7px;font-size:.72rem;margin-left:4px">{sbom['total']}</span></button>
  {sonar_tab}
</nav>

<div id="pane-overview" class="tab-pane active">
  {pane_overview}
</div>
<div id="pane-gitleaks" class="tab-pane">{pane_gitleaks}</div>
<div id="pane-trivy"    class="tab-pane">{pane_trivy}</div>
<div id="pane-zap"      class="tab-pane">{pane_zap}</div>
<div id="pane-sbom"     class="tab-pane">{pane_sbom}</div>
{sonar_pane}

<footer class="footer">
  DevSecOps Security Dashboard · généré par <code>generate_dashboard.py</code> · {now_str}
</footer>

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
    parser.add_argument(
        "--reports", default="reports",
        help="Dossier racine contenant les sous-dossiers gitleaks/, trivy/, zap/, sbom/, opa/  (défaut: ./reports)",
    )
    parser.add_argument(
        "--output", default="security-dashboard.html",
        help="Chemin du fichier HTML généré  (défaut: security-dashboard.html)",
    )
    parser.add_argument(
        "--project", default="archivage-Doc",
        help="Nom du projet affiché dans le dashboard",
    )
    parser.add_argument("--sonar-url",     default="", help="URL SonarQube ex. http://localhost:9000")
    parser.add_argument("--sonar-token",   default="", help="Token SonarQube (squ_xxx)")
    parser.add_argument("--sonar-project", default="", help="Clé du projet SonarQube")
    parser.add_argument(
        "--serve", action="store_true",
        help="Démarre un serveur HTTP local et ouvre le dashboard dans le navigateur",
    )
    args = parser.parse_args()

    reports_dir = Path(args.reports)
    output_path = Path(args.output)

    print(f"\n{'='*60}")
    print(f"  DevSecOps Dashboard Generator")
    print(f"{'='*60}")
    print(f"  Dossier rapports : {reports_dir.resolve()}")
    print(f"  Sortie           : {output_path.resolve()}")
    print()

    # ── Parsing ──────────────────────────────────────────────────────────────
    print("  [1/6] Gitleaks…")
    gitleaks = parse_gitleaks(reports_dir)
    print(f"        {gitleaks['count']} secret(s) trouvé(s)")

    print("  [2/6] Trivy…")
    trivy = parse_trivy(reports_dir)
    print(f"        {trivy['total']} CVE(s) — CRITICAL:{trivy['counts'].get('CRITICAL',0)} HIGH:{trivy['counts'].get('HIGH',0)}")

    print("  [3/6] OWASP ZAP…")
    zap = parse_zap(reports_dir)
    print(f"        {zap['total']} alerte(s) — HIGH:{zap['counts'].get('HIGH',0)} MEDIUM:{zap['counts'].get('MEDIUM',0)}")

    print("  [4/6] SBOM CycloneDX…")
    sbom = parse_sbom(reports_dir)
    print(f"        {sbom['total']} composant(s)")

    print("  [5/6] OPA Gate…")
    opa = parse_opa(reports_dir)
    gate_str = "PASS" if opa["passed"] else ("FAIL" if opa["passed"] is False else "N/A")
    print(f"        Gate : {gate_str}")

    sonar = None
    print("  [6/6] SonarQube…")
    if args.sonar_url and args.sonar_project:
        sonar = fetch_sonarqube(args.sonar_url, args.sonar_token, args.sonar_project)
        if sonar:
            print(f"        Quality Gate : {sonar['gate_status']}")
        else:
            print("        SonarQube inaccessible, onglet désactivé.")
    else:
        print("        Non configuré (utilisez --sonar-url, --sonar-token, --sonar-project)")

    # ── Génération HTML ───────────────────────────────────────────────────────
    print()
    print("  Génération du HTML…")
    html = build_html(
        gitleaks=gitleaks,
        trivy=trivy,
        zap=zap,
        sbom=sbom,
        opa=opa,
        sonar=sonar,
        project_name=args.project,
    )
    output_path.write_text(html, encoding="utf-8")
    print(f"  ✅ Dashboard généré : {output_path.resolve()}")
    print(f"     Taille           : {output_path.stat().st_size // 1024} Ko")

    # ── Serveur local optionnel ───────────────────────────────────────────────
    if args.serve:
        port = 8765
        os.chdir(output_path.parent)
        handler = http.server.SimpleHTTPRequestHandler
        handler.log_message = lambda *a: None  # silencer les logs
        server = http.server.HTTPServer(("", port), handler)
        url = f"http://localhost:{port}/{output_path.name}"
        print(f"\n  🌐 Serveur démarré sur {url}")
        print("     Ctrl+C pour arrêter.\n")
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Serveur arrêté.")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
