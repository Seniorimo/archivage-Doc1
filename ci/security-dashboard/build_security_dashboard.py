import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path


REPORTS_DIR = Path("reports")
OUT_DIR = REPORTS_DIR / "security-dashboard"
OUT_FILE = OUT_DIR / "security-dashboard.html"


# ─────────────────────────────────────────────
# DATA LOADERS
# ─────────────────────────────────────────────

def load_json(path, default):
    try:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return default
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_text(path, default="N/A"):
    try:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return default
        return p.read_text(encoding="utf-8", errors="replace").strip() or default
    except Exception:
        return default


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def esc(value):
    return html.escape(str(value if value is not None else "N/A"))


def rel(path):
    return "../" + str(path).replace("\\", "/")


def link_if_exists(path, label):
    p = REPORTS_DIR / path
    if p.exists() and p.stat().st_size > 0:
        return f'<a class="report-link" href="{esc(rel(path))}" target="_blank">↗ {esc(label)}</a>'
    return '<span class="no-link">—</span>'


def badge_status(status):
    status = str(status or "UNKNOWN").upper()
    if status in {"PASS", "SUCCESS", "OK", "TRUE"}:
        return "badge-pass"
    if status in {"UNSTABLE", "WARN", "WARNING"}:
        return "badge-warn"
    if status in {"FAIL", "FAILED", "FAILURE", "FALSE"}:
        return "badge-fail"
    return "badge-na"


def badge_severity(sev):
    sev = str(sev or "INFO").upper()
    mapping = {
        "CRITICAL": "sev-critical",
        "BLOCKER":  "sev-critical",
        "SECRET":   "sev-secret",
        "HIGH":     "sev-high",
        "MAJOR":    "sev-high",
        "MEDIUM":   "sev-medium",
        "LOW":      "sev-low",
        "MINOR":    "sev-low",
        "INFO":     "sev-info",
        "UNKNOWN":  "sev-na",
    }
    return mapping.get(sev, "sev-na")


# ─────────────────────────────────────────────
# PARSERS
# ─────────────────────────────────────────────

def count_trivy(raw):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    items = []
    for result in raw.get("Results", []) or []:
        target = result.get("Target", "N/A")
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = str(vuln.get("Severity") or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
            items.append({
                "tool": "Trivy",
                "severity": sev,
                "id": vuln.get("VulnerabilityID", "N/A"),
                "where": f"{vuln.get('PkgName', 'N/A')} {vuln.get('InstalledVersion', 'N/A')}",
                "detail": f"{target} — fix: {vuln.get('FixedVersion', 'N/A')}",
            })
    return counts, items


def count_zap(raw):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    items = []
    for site in raw.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            sev = risk.get(str(alert.get("riskcode", "0")), "INFO")
            counts[sev] = counts.get(sev, 0) + 1
            uri = "N/A"
            instances = alert.get("instances", []) or []
            if instances:
                uri = instances[0].get("uri", "N/A")
            items.append({
                "tool": "ZAP",
                "severity": sev,
                "id": alert.get("alert", alert.get("name", "N/A")),
                "where": uri,
                "detail": alert.get("desc", "N/A"),
            })
    return counts, items


def count_sonar(raw):
    counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
    items = []
    for issue in raw.get("issues", []) or []:
        sev = str(issue.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
        items.append({
            "tool": "SonarQube",
            "severity": sev,
            "id": issue.get("rule", "N/A"),
            "where": f"{issue.get('component', 'N/A')}:{issue.get('line', 'N/A')}",
            "detail": issue.get("message", "N/A"),
        })
    return counts, items


def gitleaks_items(raw):
    items = []
    if not isinstance(raw, list):
        return items
    for leak in raw:
        items.append({
            "tool": "Gitleaks",
            "severity": "SECRET",
            "id": leak.get("RuleID", "N/A"),
            "where": f"{leak.get('File', 'N/A')}:{leak.get('StartLine', leak.get('Line', 'N/A'))}",
            "detail": f"commit: {str(leak.get('Commit', 'N/A'))[:12]}",
        })
    return items


def normalize_blocking_items(opa):
    findings = []
    for leak in opa.get("gitleaks", {}).get("blocking", []) or []:
        findings.append({
            "tool": "Gitleaks",
            "severity": "SECRET",
            "id": leak.get("RuleID", "N/A"),
            "where": f"{leak.get('File', 'N/A')}:{leak.get('StartLine', leak.get('Line', 'N/A'))}",
            "detail": f"commit: {str(leak.get('Commit', 'N/A'))[:12]}",
        })
    for item in opa.get("trivy", {}).get("blocking", {}).get("items", []) or []:
        findings.append({
            "tool": "Trivy",
            "severity": item.get("severity", "N/A"),
            "id": item.get("id", "N/A"),
            "where": f"{item.get('pkg', 'N/A')} {item.get('installed', 'N/A')}",
            "detail": "Unexpected Trivy finding",
        })
    return findings


# ─────────────────────────────────────────────
# HTML COMPONENTS
# ─────────────────────────────────────────────

def render_kpi_card(label, value, sub=None, css_class=""):
    sub_html = f'<div class="kpi-sub">{esc(sub)}</div>' if sub else ""
    return f"""
      <div class="kpi-card {esc(css_class)}">
        <div class="kpi-value">{esc(str(value))}</div>
        <div class="kpi-label">{esc(label)}</div>
        {sub_html}
      </div>"""


def render_tool_card(title, status, metrics, link_html, icon, description=""):
    badge_cls = badge_status(status)
    rows = ""
    for k, v in metrics.items():
        rows += f'<div class="tool-metric"><span class="tm-key">{esc(k)}</span><span class="tm-val">{esc(str(v))}</span></div>'
    desc_html = f'<p class="tool-desc">{esc(description)}</p>' if description else ""
    return f"""
      <div class="tool-card">
        <div class="tool-head">
          <div class="tool-title-row">
            <span class="tool-icon">{icon}</span>
            <span class="tool-name">{esc(title)}</span>
          </div>
          <span class="badge {badge_cls}">{esc(status)}</span>
        </div>
        {desc_html}
        <div class="tool-metrics">{rows}</div>
        <div class="tool-link">{link_html}</div>
      </div>"""


def render_findings_table(findings):
    if not findings:
        return '<tr><td colspan="5" class="empty-row"><span class="empty-icon">✓</span> No blocking findings detected.</td></tr>'
    rows = []
    for item in findings[:80]:
        sev = item.get("severity", "INFO")
        sev_cls = badge_severity(sev)
        rows.append(f"""
          <tr>
            <td><span class="tool-pill">{esc(item.get("tool", "N/A"))}</span></td>
            <td><span class="sev-badge {sev_cls}">{esc(sev)}</span></td>
            <td class="mono">{esc(item.get("id", "N/A"))}</td>
            <td class="mono muted">{esc(item.get("where", "N/A"))}</td>
            <td class="detail-col">{esc(item.get("detail", "N/A"))}</td>
          </tr>""")
    return "\n".join(rows)


def render_detail_list(items, max_items=15):
    if not items:
        return '<div class="detail-empty">No data available.</div>'
    rows = ""
    for item in items[:max_items]:
        sev = item.get("severity", "INFO")
        sev_cls = badge_severity(sev)
        rows += f"""
          <div class="detail-row">
            <span class="sev-badge {sev_cls}">{esc(sev)}</span>
            <span class="detail-id mono">{esc(item.get("id","N/A"))}</span>
            <span class="detail-where muted mono">{esc(item.get("where","N/A"))}</span>
          </div>"""
    extra = len(items) - max_items
    more = f'<div class="detail-more">+ {extra} more findings</div>' if extra > 0 else ""
    return f'<div class="detail-list">{rows}{more}</div>'


def render_section_title(title, subtitle=""):
    sub = f'<p class="section-sub">{esc(subtitle)}</p>' if subtitle else ""
    return f'<div class="section-header"><h2 class="section-title">{esc(title)}</h2>{sub}</div>'


# ─────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────

CSS = """
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');

  :root {
    --bg:         #0b0f1a;
    --bg-panel:   #111827;
    --bg-card:    #161d2e;
    --bg-card2:   #1a2236;
    --border:     #1e2d45;
    --border-dim: #243044;
    --text:       #e2e8f4;
    --text-muted: #6b7fa3;
    --text-dim:   #4a5a78;
    --accent:     #3b82f6;
    --accent-dim: #1d4ed8;

    --c-critical: #ef4444;
    --c-secret:   #a855f7;
    --c-high:     #f97316;
    --c-medium:   #f59e0b;
    --c-low:      #3b82f6;
    --c-info:     #6b7fa3;
    --c-pass:     #10b981;
    --c-fail:     #ef4444;
    --c-warn:     #f59e0b;
    --c-na:       #4a5a78;

    --font-ui:   'Syne', sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
    --radius:    8px;
    --radius-lg: 12px;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: var(--font-ui);
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.5;
    min-height: 100vh;
  }

  /* ── HEADER ── */
  .site-header {
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
    padding: 0 40px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .header-inner {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 14px 0;
    flex-wrap: wrap;
  }
  .header-logo {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .15em;
    color: var(--text-muted);
    text-transform: uppercase;
    white-space: nowrap;
  }
  .header-logo span { color: var(--accent); }
  .header-sep { flex: 1; }
  .header-meta {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
  }
  .header-meta a { color: var(--accent); text-decoration: none; }
  .header-meta a:hover { text-decoration: underline; }

  /* ── HERO ── */
  .hero {
    background: linear-gradient(135deg, #0d1829 0%, #0b1220 60%, #0f1a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 52px 40px 44px;
    position: relative;
    overflow: hidden;
  }
  .hero::before {
    content: '';
    position: absolute;
    top: -80px; right: -80px;
    width: 420px; height: 420px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(59,130,246,.07) 0%, transparent 70%);
    pointer-events: none;
  }
  .hero-tag {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .18em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 10px;
  }
  .hero-title {
    font-size: 34px;
    font-weight: 800;
    line-height: 1.15;
    color: #fff;
    margin-bottom: 6px;
  }
  .hero-subtitle {
    font-size: 15px;
    color: var(--text-muted);
    margin-bottom: 28px;
  }
  .hero-verdict {
    display: inline-flex;
    align-items: center;
    gap: 14px;
    background: rgba(255,255,255,.04);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 14px 20px;
    backdrop-filter: blur(8px);
  }
  .verdict-label {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .verdict-value {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: .05em;
  }
  .verdict-pass { color: var(--c-pass); }
  .verdict-fail { color: var(--c-fail); }
  .verdict-warn { color: var(--c-warn); }
  .verdict-na   { color: var(--c-na); }

  /* ── LAYOUT ── */
  .main-content { padding: 36px 40px 60px; max-width: 1600px; margin: 0 auto; }

  /* ── SECTION ── */
  .section-header { margin-bottom: 18px; }
  .section-title {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--text);
  }
  .section-title::before {
    content: '';
    display: inline-block;
    width: 3px;
    height: 14px;
    background: var(--accent);
    border-radius: 2px;
    margin-right: 10px;
    vertical-align: middle;
  }
  .section-sub { color: var(--text-muted); font-size: 13px; margin-top: 4px; margin-left: 13px; }
  .section-block { margin-bottom: 44px; }

  /* ── KPI STRIP ── */
  .kpi-strip {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 12px;
    margin-bottom: 44px;
  }
  .kpi-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 16px;
    position: relative;
    overflow: hidden;
    transition: border-color .2s;
  }
  .kpi-card:hover { border-color: var(--border-dim); }
  .kpi-card::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
    opacity: .35;
  }
  .kpi-card.kpi-critical::after { background: var(--c-critical); opacity: .7; }
  .kpi-card.kpi-high::after    { background: var(--c-high);     opacity: .7; }
  .kpi-card.kpi-secret::after  { background: var(--c-secret);   opacity: .7; }
  .kpi-card.kpi-pass::after    { background: var(--c-pass);     opacity: .7; }
  .kpi-card.kpi-fail::after    { background: var(--c-fail);     opacity: .7; }
  .kpi-value {
    font-size: 30px;
    font-weight: 800;
    line-height: 1;
    color: #fff;
    margin-bottom: 6px;
    font-family: var(--font-mono);
  }
  .kpi-label {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .kpi-sub {
    font-size: 10px;
    color: var(--text-dim);
    margin-top: 4px;
    font-family: var(--font-mono);
  }

  /* ── TOOL CARDS ── */
  .tools-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
    margin-bottom: 44px;
  }
  .tool-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    transition: border-color .2s, box-shadow .2s;
  }
  .tool-card:hover {
    border-color: #2a3f62;
    box-shadow: 0 4px 24px rgba(0,0,0,.4);
  }
  .tool-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
  }
  .tool-title-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .tool-icon {
    font-size: 20px;
    line-height: 1;
  }
  .tool-name {
    font-size: 15px;
    font-weight: 700;
    color: #fff;
  }
  .tool-desc {
    font-size: 12px;
    color: var(--text-muted);
    line-height: 1.5;
  }
  .tool-metrics {
    display: flex;
    flex-direction: column;
    gap: 1px;
    background: var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .tool-metric {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 7px 12px;
    background: var(--bg-card2);
    font-size: 12px;
  }
  .tm-key { color: var(--text-muted); }
  .tm-val { font-weight: 700; color: var(--text); font-family: var(--font-mono); }
  .tool-link { font-size: 12px; }
  .report-link {
    color: var(--accent);
    text-decoration: none;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 5px 10px;
    border: 1px solid rgba(59,130,246,.3);
    border-radius: 5px;
    transition: background .15s;
  }
  .report-link:hover { background: rgba(59,130,246,.1); }
  .no-link { color: var(--text-dim); font-size: 12px; }

  /* ── BADGES ── */
  .badge {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
    padding: 3px 9px;
    border-radius: 999px;
    white-space: nowrap;
  }
  .badge-pass { background: rgba(16,185,129,.15); color: var(--c-pass); border: 1px solid rgba(16,185,129,.3); }
  .badge-fail { background: rgba(239,68,68,.15);  color: var(--c-fail); border: 1px solid rgba(239,68,68,.3); }
  .badge-warn { background: rgba(245,158,11,.15); color: var(--c-warn); border: 1px solid rgba(245,158,11,.3); }
  .badge-na   { background: rgba(74,90,120,.2);   color: var(--c-na);   border: 1px solid rgba(74,90,120,.3); }

  .sev-badge {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .07em;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: 4px;
    white-space: nowrap;
    font-family: var(--font-mono);
  }
  .sev-critical { background: rgba(239,68,68,.2);  color: #fca5a5; border: 1px solid rgba(239,68,68,.4); }
  .sev-secret   { background: rgba(168,85,247,.2); color: #d8b4fe; border: 1px solid rgba(168,85,247,.4); }
  .sev-high     { background: rgba(249,115,22,.2); color: #fdba74; border: 1px solid rgba(249,115,22,.4); }
  .sev-medium   { background: rgba(245,158,11,.2); color: #fcd34d; border: 1px solid rgba(245,158,11,.4); }
  .sev-low      { background: rgba(59,130,246,.2); color: #93c5fd; border: 1px solid rgba(59,130,246,.4); }
  .sev-info     { background: rgba(107,127,163,.15); color: var(--text-muted); border: 1px solid var(--border); }
  .sev-na       { background: rgba(74,90,120,.15);   color: var(--text-dim);   border: 1px solid var(--border-dim); }

  /* ── TABLE ── */
  .table-wrap {
    overflow-x: auto;
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  thead {
    background: var(--bg-card2);
    position: sticky;
    top: 53px;
  }
  th {
    padding: 11px 14px;
    text-align: left;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 10px 14px;
    border-bottom: 1px solid rgba(30,45,69,.6);
    vertical-align: middle;
    color: var(--text);
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,.025); }
  .tool-pill {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .06em;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(59,130,246,.1);
    color: #93c5fd;
    border: 1px solid rgba(59,130,246,.2);
    text-transform: uppercase;
    font-family: var(--font-mono);
  }
  .mono    { font-family: var(--font-mono); font-size: 12px; }
  .muted   { color: var(--text-muted); }
  .detail-col { max-width: 300px; color: var(--text-muted); font-size: 12px; }
  .empty-row {
    text-align: center;
    padding: 36px 20px !important;
    color: var(--c-pass);
    font-weight: 600;
    font-size: 13px;
  }
  .empty-icon { margin-right: 8px; }

  /* ── DETAIL BREAKDOWN ── */
  .breakdown-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 16px;
  }
  .breakdown-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .breakdown-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 18px;
    background: var(--bg-card2);
    border-bottom: 1px solid var(--border);
  }
  .breakdown-title {
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .breakdown-count {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 7px;
  }
  .breakdown-body { padding: 14px 18px; }
  .detail-list { display: flex; flex-direction: column; gap: 8px; }
  .detail-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 0;
    border-bottom: 1px solid rgba(30,45,69,.5);
    flex-wrap: wrap;
  }
  .detail-row:last-child { border-bottom: none; }
  .detail-id   { font-size: 12px; font-weight: 600; color: var(--text); }
  .detail-where { font-size: 11px; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .detail-more { font-size: 11px; color: var(--text-dim); font-style: italic; padding-top: 8px; text-align: center; }
  .detail-empty {
    font-size: 12px;
    color: var(--text-dim);
    text-align: center;
    padding: 20px 0;
    font-style: italic;
  }

  /* ── FOOTER ── */
  .site-footer {
    background: var(--bg-panel);
    border-top: 1px solid var(--border);
    padding: 22px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    flex-wrap: wrap;
  }
  .footer-left {
    font-size: 11px;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }
  .footer-right {
    font-size: 11px;
    color: var(--text-dim);
  }
  .footer-tag {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--text-dim);
  }
  .footer-tag::before {
    content: '';
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    opacity: .6;
  }

  @media (max-width: 768px) {
    .hero, .main-content { padding-left: 20px; padding-right: 20px; }
    .site-header { padding: 0 20px; }
    .hero-title { font-size: 24px; }
    .kpi-strip { grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); }
    .site-footer { padding: 18px 20px; }
  }
"""


# ─────────────────────────────────────────────
# PAGE RENDER
# ─────────────────────────────────────────────

def render_page(
    job_name, build_number, build_url, generated_at,
    verdict, opa_status,
    gitleaks_total, gitleaks_blocking, gitleaks_expected,
    trivy_counts, trivy_blocking, trivy_all,
    zap_counts, zap_blocking, zap_all,
    sonar_counts, sonar_all,
    gitleaks_all,
    blocking_findings,
    opa_result,
    opa_reasons,
    sbom_json_exists, sbom_xml_exists,
):
    total_findings = gitleaks_total + sum(trivy_counts.values()) + sum(zap_counts.values()) + sum(sonar_counts.values())
    total_critical = trivy_counts.get("CRITICAL", 0) + sonar_counts.get("CRITICAL", 0) + sonar_counts.get("BLOCKER", 0)
    total_high     = trivy_counts.get("HIGH", 0) + zap_counts.get("HIGH", 0) + sonar_counts.get("MAJOR", 0)
    blocking_count = len(blocking_findings)

    # verdict display
    if verdict.upper() in {"PASS", "SUCCESS", "OK"}:
        verdict_cls = "verdict-pass"
    elif verdict.upper() in {"FAIL", "FAILURE", "FAILED"}:
        verdict_cls = "verdict-fail"
    elif verdict.upper() in {"UNSTABLE", "WARN"}:
        verdict_cls = "verdict-warn"
    else:
        verdict_cls = "verdict-na"

    jenkins_link = ""
    if build_url:
        jenkins_link = f'<a href="{esc(build_url)}" target="_blank">↗ Open Jenkins Build</a>'

    # KPI cards
    kpi_pass_fail = "kpi-pass" if blocking_count == 0 else "kpi-fail"
    kpi_critical_cls = "kpi-critical" if total_critical > 0 else ""
    kpi_high_cls     = "kpi-high"     if total_high > 0     else ""
    kpi_secret_cls   = "kpi-secret"   if gitleaks_total > 0 else ""
    opa_kpi_cls      = "kpi-pass" if opa_status == "PASS" else ("kpi-fail" if opa_status == "FAIL" else "")

    kpi_strip = "".join([
        render_kpi_card("Total Findings", total_findings),
        render_kpi_card("Blocking", blocking_count, css_class=kpi_pass_fail),
        render_kpi_card("Critical", total_critical, css_class=kpi_critical_cls),
        render_kpi_card("High", total_high, css_class=kpi_high_cls),
        render_kpi_card("Secrets", gitleaks_total, css_class=kpi_secret_cls),
        render_kpi_card("OPA Gate", opa_status, css_class=opa_kpi_cls),
        render_kpi_card("Scanners", "6"),
    ])

    # Gitleaks status
    gl_status = "PASS" if int(gitleaks_blocking or 0) == 0 else "FAIL"
    gl_card = render_tool_card(
        "Gitleaks", gl_status,
        {
            "Total secrets":    gitleaks_total,
            "Expected":         gitleaks_expected if gitleaks_expected != "N/A" else "—",
            "Blocking":         gitleaks_blocking,
        },
        link_if_exists(Path("gitleaks") / "gitleaks-report.json", "JSON Report"),
        "🔑",
        "Secret & credential leak detection in source code and git history.",
    )

    # Trivy status
    trivy_b_crit = int(trivy_blocking.get("critical", 0) or 0)
    trivy_b_high = int(trivy_blocking.get("high", 0) or 0)
    tv_status = "PASS" if trivy_b_crit == 0 and trivy_b_high == 0 else "FAIL"
    tv_card = render_tool_card(
        "Trivy", tv_status,
        {
            "Critical":         trivy_counts.get("CRITICAL", 0),
            "High":             trivy_counts.get("HIGH", 0),
            "Medium":           trivy_counts.get("MEDIUM", 0),
            "Blocking critical": trivy_blocking.get("critical", "—"),
            "Blocking high":    trivy_blocking.get("high", "—"),
        },
        link_if_exists(Path("trivy") / "trivy-report.json", "JSON Report"),
        "🛡",
        "Container & filesystem vulnerability scanner (CVE database).",
    )

    # ZAP status
    zap_b_high = int(zap_blocking.get("high", 0) or 0)
    zap_status = "PASS" if zap_b_high == 0 else "FAIL"
    zap_card = render_tool_card(
        "OWASP ZAP", zap_status,
        {
            "High":             zap_counts.get("HIGH", 0),
            "Medium":           zap_counts.get("MEDIUM", 0),
            "Low":              zap_counts.get("LOW", 0),
            "Blocking high":    zap_blocking.get("high", "—"),
        },
        link_if_exists(Path("zap") / "zap-report.html", "HTML Report"),
        "🌐",
        "Dynamic application security testing (DAST) — active scanner.",
    )

    # Sonar status
    sonar_card = render_tool_card(
        "SonarQube", "INFO",
        {
            "Blocker":          sonar_counts.get("BLOCKER", 0),
            "Critical":         sonar_counts.get("CRITICAL", 0),
            "Major":            sonar_counts.get("MAJOR", 0),
            "Minor":            sonar_counts.get("MINOR", 0),
        },
        link_if_exists(Path("sonar") / "sonar-vulnerabilities.json", "JSON Export"),
        "🔬",
        "Static code analysis — code quality and security vulnerabilities.",
    )

    # OPA status
    opa_card = render_tool_card(
        "OPA Gate", opa_status,
        {
            "Gate result":      opa_result,
            "Blocking findings": blocking_count,
        },
        link_if_exists(Path("opa") / "input.json", "Input JSON"),
        "⚖️",
        "Open Policy Agent — policy enforcement gate for all scan results.",
    )

    # SBOM status
    sbom_metrics = {
        "CycloneDX JSON": "available" if sbom_json_exists else "N/A",
        "CycloneDX XML":  "available" if sbom_xml_exists  else "N/A",
    }
    sbom_card = render_tool_card(
        "SBOM", "INFO", sbom_metrics,
        link_if_exists(Path("sbom") / "bom.json", "BOM JSON"),
        "📦",
        "Software Bill of Materials — CycloneDX format artifact inventory.",
    )

    tools_grid = f"""
      <div class="tools-grid">
        {gl_card}{tv_card}{zap_card}{sonar_card}{opa_card}{sbom_card}
      </div>"""

    # Blocking table
    blocking_table = f"""
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Severity</th>
              <th>ID / Rule / CVE</th>
              <th>Component / File</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>{render_findings_table(blocking_findings)}</tbody>
        </table>
      </div>"""

    # Detailed breakdown
    def breakdown_card(title, icon, items, count):
        return f"""
          <div class="breakdown-card">
            <div class="breakdown-header">
              <div class="breakdown-title">{icon} {esc(title)}</div>
              <span class="breakdown-count">{count}</span>
            </div>
            <div class="breakdown-body">{render_detail_list(items)}</div>
          </div>"""

    opa_reason_items = [{"severity": "FAIL", "id": r, "where": ""} for r in (opa_reasons or [])]

    breakdown = f"""
      <div class="breakdown-grid">
        {breakdown_card("Gitleaks Secrets",  "🔑", gitleaks_all, gitleaks_total)}
        {breakdown_card("Trivy Critical/High","🛡", [i for i in trivy_all if i["severity"] in {"CRITICAL","HIGH"}],
                         trivy_counts.get("CRITICAL",0) + trivy_counts.get("HIGH",0))}
        {breakdown_card("ZAP Alerts",         "🌐", [i for i in zap_all   if i["severity"] in {"HIGH","MEDIUM"}],
                         zap_counts.get("HIGH",0) + zap_counts.get("MEDIUM",0))}
        {breakdown_card("Sonar Issues",       "🔬", [i for i in sonar_all if i["severity"] in {"BLOCKER","CRITICAL","MAJOR"}],
                         sonar_counts.get("BLOCKER",0)+sonar_counts.get("CRITICAL",0)+sonar_counts.get("MAJOR",0))}
        {breakdown_card("OPA Reasons",        "⚖️", opa_reason_items, len(opa_reason_items))}
      </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Dashboard — {esc(job_name)}</title>
  <style>{CSS}</style>
</head>
<body>

  <!-- ── TOP NAV ── -->
  <header class="site-header">
    <div class="header-inner">
      <div class="header-logo"><span>◈</span> DevSecOps Dashboard</div>
      <div class="header-sep"></div>
      <div class="header-meta">
        <span>Build <strong>#{esc(build_number)}</strong></span>
        <span>{esc(generated_at)}</span>
        {jenkins_link}
      </div>
    </div>
  </header>

  <!-- ── HERO ── -->
  <div class="hero">
    <div class="hero-tag">Security Scan Report</div>
    <h1 class="hero-title">{esc(job_name)}</h1>
    <p class="hero-subtitle">Automated security pipeline — {esc(generated_at)}</p>
    <div class="hero-verdict">
      <span class="verdict-label">Global Verdict</span>
      <span class="verdict-value {verdict_cls}">{esc(verdict)}</span>
    </div>
  </div>

  <!-- ── MAIN ── -->
  <main class="main-content">

    <!-- KPI Strip -->
    <div class="section-block">
      {render_section_title("Key Metrics", "Aggregated findings across all security scanners")}
      <div class="kpi-strip">{kpi_strip}</div>
    </div>

    <!-- Tool Cards -->
    <div class="section-block">
      {render_section_title("Security Tools Overview", "Status and findings per scanner")}
      {tools_grid}
    </div>

    <!-- Blocking Findings -->
    <div class="section-block">
      {render_section_title("Blocking / Unexpected Findings",
          f"{blocking_count} finding(s) that block the pipeline")}
      {blocking_table}
    </div>

    <!-- Detailed Breakdown -->
    <div class="section-block">
      {render_section_title("Detailed Breakdown", "Top findings per scanner (critical & high)")}
      {breakdown}
    </div>

  </main>

  <!-- ── FOOTER ── -->
  <footer class="site-footer">
    <div class="footer-left">
      Project: <strong>{esc(job_name)}</strong> &nbsp;·&nbsp;
      Build: <strong>#{esc(build_number)}</strong> &nbsp;·&nbsp;
      {esc(generated_at)}
    </div>
    <div class="footer-right">
      <span class="footer-tag">Auto-generated by security pipeline</span>
    </div>
  </footer>

</body>
</html>"""


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    gitleaks = load_json(REPORTS_DIR / "gitleaks" / "gitleaks-report.json", [])
    trivy    = load_json(REPORTS_DIR / "trivy"    / "trivy-report.json",    {"Results": []})
    zap      = load_json(REPORTS_DIR / "zap"      / "zap-report.json",      {"site": [{"alerts": []}]})
    sonar    = load_json(REPORTS_DIR / "sonar"    / "sonar-vulnerabilities.json", {"issues": [], "total": 0})
    opa      = load_json(REPORTS_DIR / "opa"      / "input.json", {})
    opa_result_raw = load_text(REPORTS_DIR / "opa" / "opa-result.txt", "N/A").lower()

    trivy_counts, trivy_all = count_trivy(trivy)
    zap_counts,   zap_all   = count_zap(zap)
    sonar_counts, sonar_all = count_sonar(sonar)
    gitleaks_all             = gitleaks_items(gitleaks)

    gitleaks_total    = len(gitleaks_all)
    gitleaks_blocking = opa.get("gitleaks", {}).get("blocking_count", gitleaks_total)
    gitleaks_expected = opa.get("gitleaks", {}).get("expected_count", "N/A")
    trivy_blocking    = opa.get("trivy", {}).get("blocking", {})
    zap_blocking      = opa.get("zap",   {}).get("blocking", {})
    opa_reasons       = opa.get("reasons", [])

    blocking_findings = normalize_blocking_items(opa)
    if not opa:
        blocking_findings = [
            item for item in gitleaks_all + trivy_all + zap_all
            if item.get("severity") in {"SECRET", "CRITICAL", "HIGH"}
        ]

    build_result = os.environ.get("SECURITY_BUILD_RESULT", "N/A")
    opa_status   = "PASS" if opa_result_raw == "true" else ("FAIL" if opa_result_raw == "false" else "N/A")
    verdict      = "PASS" if opa_status == "PASS" and build_result.upper() in {"SUCCESS", "N/A"} else build_result
    if blocking_findings or opa_status == "FAIL":
        verdict = "FAIL"

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    job_name     = os.environ.get("JOB_NAME",    "archivage-doc")
    build_number = os.environ.get("BUILD_NUMBER", "N/A")
    build_url    = os.environ.get("BUILD_URL",    "")

    sbom_json_exists = (REPORTS_DIR / "sbom" / "bom.json").exists()
    sbom_xml_exists  = (REPORTS_DIR / "sbom" / "bom.xml").exists()

    html_doc = render_page(
        job_name=job_name,
        build_number=build_number,
        build_url=build_url,
        generated_at=generated_at,
        verdict=verdict,
        opa_status=opa_status,
        gitleaks_total=gitleaks_total,
        gitleaks_blocking=gitleaks_blocking,
        gitleaks_expected=gitleaks_expected,
        trivy_counts=trivy_counts,
        trivy_blocking=trivy_blocking,
        trivy_all=trivy_all,
        zap_counts=zap_counts,
        zap_blocking=zap_blocking,
        zap_all=zap_all,
        sonar_counts=sonar_counts,
        sonar_all=sonar_all,
        gitleaks_all=gitleaks_all,
        blocking_findings=blocking_findings,
        opa_result=opa_result_raw,
        opa_reasons=opa_reasons,
        sbom_json_exists=sbom_json_exists,
        sbom_xml_exists=sbom_xml_exists,
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(html_doc, encoding="utf-8")
    print(f"Security dashboard generated: {OUT_FILE}")


if __name__ == "__main__":
    main()