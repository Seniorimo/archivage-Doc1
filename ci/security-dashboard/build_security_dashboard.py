import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path


REPORTS_DIR = Path("reports")
OUT_DIR = REPORTS_DIR / "security-dashboard"
OUT_FILE = OUT_DIR / "security-dashboard.html"


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


def esc(value):
    return html.escape(str(value if value is not None else "N/A"))


def badge_class(status):
    status = str(status or "UNKNOWN").upper()
    if status in {"PASS", "SUCCESS", "OK", "TRUE"}:
        return "ok"
    if status in {"UNSTABLE", "WARN", "WARNING"}:
        return "warn"
    if status in {"FAIL", "FAILED", "FAILURE", "FALSE"}:
        return "fail"
    return "na"


def rel(path):
    return "../" + str(path).replace("\\", "/")


def link_if_exists(path, label):
    p = REPORTS_DIR / path
    if p.exists() and p.stat().st_size > 0:
        return f'<a href="{esc(rel(path))}">{esc(label)}</a>'
    return "N/A"


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
                "detail": f"{target} | fix: {vuln.get('FixedVersion', 'N/A')}",
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


def card(title, status, metrics, link):
    rows = "".join(f"<li><span>{esc(k)}</span><strong>{esc(v)}</strong></li>" for k, v in metrics.items())
    return f"""
      <section class="card">
        <div class="card-head">
          <h2>{esc(title)}</h2>
          <span class="badge {badge_class(status)}">{esc(status)}</span>
        </div>
        <ul class="metrics">{rows}</ul>
        <div class="links">{link}</div>
      </section>
    """


def render_findings(findings):
    if not findings:
        return '<tr><td colspan="5" class="empty">Aucun finding bloquant non attendu.</td></tr>'
    rows = []
    for item in findings[:80]:
        rows.append(f"""
          <tr>
            <td>{esc(item.get("tool"))}</td>
            <td><span class="severity">{esc(item.get("severity"))}</span></td>
            <td>{esc(item.get("id"))}</td>
            <td>{esc(item.get("where"))}</td>
            <td>{esc(item.get("detail"))}</td>
          </tr>
        """)
    return "\n".join(rows)


def main():
    gitleaks = load_json(REPORTS_DIR / "gitleaks" / "gitleaks-report.json", [])
    trivy = load_json(REPORTS_DIR / "trivy" / "trivy-report.json", {"Results": []})
    zap = load_json(REPORTS_DIR / "zap" / "zap-report.json", {"site": [{"alerts": []}]})
    sonar = load_json(REPORTS_DIR / "sonar" / "sonar-vulnerabilities.json", {"issues": [], "total": 0})
    opa = load_json(REPORTS_DIR / "opa" / "input.json", {})
    opa_result = load_text(REPORTS_DIR / "opa" / "opa-result.txt", "N/A").lower()

    trivy_counts, trivy_all = count_trivy(trivy)
    zap_counts, zap_all = count_zap(zap)
    sonar_counts, sonar_all = count_sonar(sonar)
    gitleaks_all = gitleaks_items(gitleaks)

    gitleaks_total = len(gitleaks_all)
    gitleaks_blocking = opa.get("gitleaks", {}).get("blocking_count", gitleaks_total)
    trivy_blocking = opa.get("trivy", {}).get("blocking", {})
    zap_blocking = opa.get("zap", {}).get("blocking", {})

    blocking_findings = normalize_blocking_items(opa)
    if not opa:
        blocking_findings = [
            item for item in gitleaks_all + trivy_all + zap_all
            if item.get("severity") in {"SECRET", "CRITICAL", "HIGH"}
        ]

    build_result = os.environ.get("SECURITY_BUILD_RESULT", "N/A")
    opa_status = "PASS" if opa_result == "true" else ("FAIL" if opa_result == "false" else "N/A")
    verdict = "PASS" if opa_status == "PASS" and build_result.upper() in {"SUCCESS", "N/A"} else build_result
    if blocking_findings or opa_status == "FAIL":
        verdict = "FAIL"

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    job_name = os.environ.get("JOB_NAME", "N/A")
    build_number = os.environ.get("BUILD_NUMBER", "N/A")
    build_url = os.environ.get("BUILD_URL", "")

    cards = [
        card("Gitleaks", "PASS" if int(gitleaks_blocking or 0) == 0 else "FAIL", {
            "Total secrets": gitleaks_total,
            "Expected": opa.get("gitleaks", {}).get("expected_count", "N/A"),
            "Blocking": gitleaks_blocking,
        }, link_if_exists(Path("gitleaks") / "gitleaks-report.json", "Rapport JSON")),
        card("Trivy", "PASS" if int(trivy_blocking.get("critical", 0) or 0) == 0 and int(trivy_blocking.get("high", 0) or 0) == 0 else "FAIL", {
            "Critical": trivy_counts.get("CRITICAL", 0),
            "High": trivy_counts.get("HIGH", 0),
            "Blocking critical": trivy_blocking.get("critical", "N/A"),
            "Blocking high": trivy_blocking.get("high", "N/A"),
        }, link_if_exists(Path("trivy") / "trivy-report.json", "Rapport JSON")),
        card("ZAP", "PASS" if int(zap_blocking.get("high", 0) or 0) == 0 else "FAIL", {
            "High": zap_counts.get("HIGH", 0),
            "Medium": zap_counts.get("MEDIUM", 0),
            "Blocking high": zap_blocking.get("high", "N/A"),
        }, link_if_exists(Path("zap") / "zap-report.html", "Rapport HTML")),
        card("SonarQube", "INFO", {
            "Blocker": sonar_counts.get("BLOCKER", 0),
            "Critical": sonar_counts.get("CRITICAL", 0),
            "Major": sonar_counts.get("MAJOR", 0),
        }, link_if_exists(Path("sonar") / "sonar-vulnerabilities.json", "Export JSON")),
        card("OPA Gate", opa_status, {
            "Result": opa_result,
            "Blocking findings": len(blocking_findings),
        }, link_if_exists(Path("opa") / "input.json", "Input JSON")),
        card("SBOM", "INFO", {
            "CycloneDX JSON": "available" if (REPORTS_DIR / "sbom" / "bom.json").exists() else "N/A",
            "CycloneDX XML": "available" if (REPORTS_DIR / "sbom" / "bom.xml").exists() else "N/A",
        }, link_if_exists(Path("sbom") / "bom.json", "BOM JSON")),
    ]

    html_doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Dashboard - archivage-doc</title>
  <style>
    :root {{
      --bg: #f6f8fb; --panel: #ffffff; --text: #182230; --muted: #667085;
      --border: #d9e2ec; --ok: #067647; --warn: #b54708; --fail: #b42318; --na: #475467;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, Arial, sans-serif; background: var(--bg); color: var(--text); }}
    header {{ padding: 28px 32px; background: #111827; color: #fff; }}
    header h1 {{ margin: 0 0 10px; font-size: 28px; }}
    header p {{ margin: 4px 0; color: #d0d5dd; }}
    .verdict {{ display: inline-flex; align-items: center; gap: 10px; margin-top: 16px; padding: 10px 14px; border-radius: 6px; background: #fff; color: #111827; font-weight: 700; }}
    .wrap {{ padding: 24px 32px 40px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; box-shadow: 0 1px 2px rgba(16,24,40,.05); }}
    .card-head {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 12px; }}
    .card h2 {{ margin: 0; font-size: 17px; }}
    .badge {{ border-radius: 999px; padding: 4px 10px; color: #fff; font-size: 12px; font-weight: 700; }}
    .ok {{ background: var(--ok); }} .warn {{ background: var(--warn); }} .fail {{ background: var(--fail); }} .na {{ background: var(--na); }}
    .metrics {{ list-style: none; padding: 0; margin: 0; }}
    .metrics li {{ display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-top: 1px solid #eef2f6; }}
    .metrics span {{ color: var(--muted); }}
    .links {{ margin-top: 12px; }}
    a {{ color: #175cd3; text-decoration: none; font-weight: 600; }}
    a:hover {{ text-decoration: underline; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid #eef2f6; text-align: left; vertical-align: top; }}
    th {{ background: #f2f4f7; font-size: 12px; text-transform: uppercase; color: #475467; letter-spacing: .04em; }}
    .severity {{ font-weight: 700; color: var(--fail); }}
    .empty {{ text-align: center; color: var(--muted); padding: 28px; }}
  </style>
</head>
<body>
  <header>
    <h1>Security Dashboard - archivage-doc</h1>
    <p>Job: {esc(job_name)} | Build: {esc(build_number)} | Généré: {esc(generated_at)}</p>
    <p>{f'<a href="{esc(build_url)}" style="color:#93c5fd">Ouvrir le build Jenkins</a>' if build_url else 'Build URL: N/A'}</p>
    <div class="verdict"><span>Verdict global</span><span class="badge {badge_class(verdict)}">{esc(verdict)}</span></div>
  </header>
  <main class="wrap">
    <section class="grid">{''.join(cards)}</section>
    <section>
      <h2>Findings bloquants non attendus</h2>
      <table>
        <thead><tr><th>Outil</th><th>Sévérité</th><th>ID / règle</th><th>Emplacement</th><th>Détail</th></tr></thead>
        <tbody>{render_findings(blocking_findings)}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(html_doc, encoding="utf-8")
    print(f"Security dashboard generated: {OUT_FILE}")


if __name__ == "__main__":
    main()
