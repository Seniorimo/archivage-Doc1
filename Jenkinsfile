pipeline {

    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 90, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
    }

    environment {
        APP_NAME        = 'archivage-Doc'
        APP_CONTAINER   = 'app-archivage'
        MYSQL_CONTAINER = 'mysql-archivage'
        NETWORK_NAME    = 'archivage-net'
        APP_PORT        = '8090'
        MAVEN_REPO      = '/var/jenkins_home/.m2/repository'
        SONARQUBE_ENV   = 'sonar'
    }

    stages {

        // ── 1. INIT ──────────────────────────────────────────────────────────
        stage('Init') {
            steps {
                script {
                    env.PROJECT_DIR = "${env.WORKSPACE}/src"
                    env.TRIVY_CACHE  = "${env.WORKSPACE}/src/.trivycache"
                    env.JENKINS_UID  = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID  = sh(returnStdout: true, script: 'id -g').trim()

                    echo "✅ Environment initialized"
                    echo "   PROJECT_DIR: ${env.PROJECT_DIR}"
                    echo "   JENKINS_UID: ${env.JENKINS_UID}"
                }
            }
        }

        // ── 2. CHECKOUT ──────────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                deleteDir()

                dir('src') {
                    checkout scm
                }

                script {
                    env.GIT_SHA = sh(
                        returnStdout: true,
                        script: 'cd "$PROJECT_DIR" && git rev-parse HEAD'
                    ).trim()

                    if (!env.GIT_SHA?.trim()) {
                        error("❌ Failed to extract GIT_SHA")
                    }

                    env.GIT_SHORT_SHA = env.GIT_SHA.take(7)
                    echo "✅ Commit: ${env.GIT_SHA}"
                    echo "✅ Short SHA: ${env.GIT_SHORT_SHA}"
                }
            }
        }

        // ── 3. LOGIN & PULL IMAGE ────────────────────────────────────────────
        stage('Login & Pull Image') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'docker-hub-creds',
                    usernameVariable: 'DOCKER_HUB_USERNAME',
                    passwordVariable: 'DOCKER_HUB_PASSWORD'
                )]) {
                    script {
                        def tags = [env.GIT_SHORT_SHA, "latest", "main"]
                        def imageFound = false

                        for (tag in tags) {
                            try {
                                sh """
                                    set -eu
                                    echo "📥 Attempting to pull: \$DOCKER_HUB_USERNAME/archivage-app:${tag}"
                                    echo "\$DOCKER_HUB_PASSWORD" | docker login -u "\$DOCKER_HUB_USERNAME" --password-stdin
                                    docker pull "\$DOCKER_HUB_USERNAME/archivage-app:${tag}"
                                    echo "✅ Image pulled successfully"
                                """
                                env.RESOLVED_IMAGE_TAG = tag
                                imageFound = true
                                break
                            } catch (Exception e) {
                                echo "⚠️  Tag not found: ${tag}, trying next..."
                            }
                        }

                        if (!imageFound) {
                            error("❌ No image found on Docker Hub with tags: ${tags.join(', ')}")
                        }

                        env.DOCKER_IMAGE = "\${env.DOCKER_HUB_USERNAME}/archivage-app:${env.RESOLVED_IMAGE_TAG}"
                        echo "✅ Using image: ${env.DOCKER_IMAGE}"
                    }
                }
            }
        }

        // ── 4. PREPARE WORKSPACE ─────────────────────────────────────────────
        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== PREPARE WORKSPACE ==="

                    rm -rf reports .trivycache policy
                    mkdir -p \
                        reports/gitleaks \
                        reports/trivy \
                        reports/sbom \
                        reports/zap \
                        reports/opa \
                        reports/dashboard \
                        .trivycache \
                        policy

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 \
                        || docker network create "$NETWORK_NAME"

                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

allow if {
    input.trivy.critical == 0
    input.trivy.high <= 5
    count(input.gitleaks) == 0
    input.zap.high <= 3
}
REGO

                    # ── generate_dashboard.py ──────────────────────────────
                    cat > generate_dashboard.py <<'PYDASH'
#!/usr/bin/env python3
"""
generate_dashboard.py — Security Dashboard consolidé pour archivage-Doc
Agrège Gitleaks, Trivy, ZAP, OPA, SBOM (et SonarQube si dispo).
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Cannot parse {path}: {e}", file=sys.stderr)
        return default

def fetch_sonar(base_url, token, project_key):
    if not base_url or not token or not project_key:
        return None
    try:
        import base64
        creds = base64.b64encode(f"{token}:".encode()).decode()
        url = (
            f"{base_url.rstrip('/')}/api/measures/component"
            f"?component={project_key}"
            f"&metricKeys=bugs,vulnerabilities,code_smells,"
            f"coverage,duplicated_lines_density,security_hotspots"
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            measures = {
                m["metric"]: m.get("value", "N/A")
                for m in data.get("component", {}).get("measures", [])
            }
            return measures
    except Exception as e:
        print(f"[WARN] SonarQube fetch failed: {e}", file=sys.stderr)
        return None

def badge(value, label, color):
    return (
        f'<div class="badge" style="background:{color}">'
        f'<div class="num">{value}</div>'
        f'<div class="lbl">{label}</div></div>'
    )

def severity_color(sev):
    return {"CRITICAL": "#8e1a1a", "HIGH": "#c0392b",
            "MEDIUM": "#e67e22", "LOW": "#c8a200", "INFO": "#2980b9"}.get(sev, "#999")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports",       default="reports")
    ap.add_argument("--output",        default="reports/dashboard/security-dashboard.html")
    ap.add_argument("--project",       default="archivage-Doc")
    ap.add_argument("--sonar-url",     default="")
    ap.add_argument("--sonar-token",   default="")
    ap.add_argument("--sonar-project", default="")
    args = ap.parse_args()

    r = Path(args.reports)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Load data ──────────────────────────────────────────────────────
    gitleaks_data = load_json(r / "gitleaks/gitleaks-report.json", [])
    trivy_data    = load_json(r / "trivy/trivy-report.json", {"Results": []})
    zap_data      = load_json(r / "zap/zap-report.json", {"site": [{"alerts": []}]})
    opa_result    = (r / "opa/opa-result.txt").read_text(encoding="utf-8").strip() \
                        if (r / "opa/opa-result.txt").exists() else "unknown"
    sbom_exists   = (r / "sbom/bom.json").exists() or (r / "sbom/bom.xml").exists()
    opa_input     = load_json(r / "opa/input.json", {})
    sonar_data    = fetch_sonar(args.sonar_url, args.sonar_token, args.sonar_project)

    # ── Trivy stats ────────────────────────────────────────────────────
    trivy_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    trivy_vulns = []
    for res in trivy_data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            s = (v.get("Severity") or "").upper()
            if s in trivy_sev:
                trivy_sev[s] += 1
            trivy_vulns.append(v)

    # ── ZAP stats ──────────────────────────────────────────────────────
    RISK_LABEL = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    RISK_COLOR = {"3": "#c0392b", "2": "#e67e22", "1": "#f1c40f", "0": "#2980b9"}
    zap_counts = {"3": 0, "2": 0, "1": 0, "0": 0}
    zap_alerts = []
    for site in zap_data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            rc = str(alert.get("riskcode", "0"))
            zap_counts[rc] = zap_counts.get(rc, 0) + 1
            zap_alerts.append(alert)

    gitleaks_count = len(gitleaks_data) if isinstance(gitleaks_data, list) else 0
    gate_color   = "#27ae60" if opa_result == "true" else "#c0392b"
    gate_label   = "PASSED ✅" if opa_result == "true" else "BLOCKED ❌"

    # ── Trivy rows ─────────────────────────────────────────────────────
    trivy_rows = ""
    for v in sorted(trivy_vulns, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(
            (x.get("Severity","LOW")).upper()) if (x.get("Severity","LOW")).upper()
            in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99)[:50]:
        sev = (v.get("Severity") or "LOW").upper()
        color = severity_color(sev)
        cve   = v.get("VulnerabilityID", "N/A")
        pkg   = v.get("PkgName", "N/A")
        ver   = v.get("InstalledVersion", "N/A")
        fix   = v.get("FixedVersion", "—")
        title = (v.get("Title") or "")[:80]
        trivy_rows += f"""<tr>
            <td><span class="badge-inline" style="background:{color}">{sev}</span></td>
            <td>{cve}</td><td>{pkg}</td><td>{ver}</td>
            <td style="color:#27ae60">{fix}</td>
            <td style="font-size:12px">{title}</td></tr>"""

    # ── ZAP rows ───────────────────────────────────────────────────────
    zap_rows = ""
    for a in sorted(zap_alerts, key=lambda x: -int(x.get("riskcode", 0)))[:30]:
        rc    = str(a.get("riskcode", "0"))
        name  = (a.get("alert") or a.get("name") or "?")
        desc  = (a.get("desc") or "")[:200].replace("<","&lt;").replace(">","&gt;")
        sol   = (a.get("solution") or "")[:200].replace("<","&lt;").replace(">","&gt;")
        url   = next((i.get("uri","") for i in a.get("instances",[])[:1]), "")
        color = RISK_COLOR.get(rc, "#999")
        label = RISK_LABEL.get(rc, rc)
        zap_rows += f"""<tr>
            <td><span class="badge-inline" style="background:{color}">{label}</span></td>
            <td><strong>{name}</strong><br><small style="color:#777">{url}</small></td>
            <td style="font-size:12px">{desc}</td>
            <td style="font-size:12px">{sol}</td></tr>"""

    # ── Gitleaks rows ──────────────────────────────────────────────────
    gitleaks_rows = ""
    for leak in (gitleaks_data[:20] if isinstance(gitleaks_data, list) else []):
        rule    = leak.get("RuleID", "?")
        file_   = leak.get("File", "?")
        line    = leak.get("StartLine", "?")
        commit  = (leak.get("Commit") or "")[:8]
        gitleaks_rows += f"""<tr>
            <td><span class="badge-inline" style="background:#8e1a1a">SECRET</span></td>
            <td>{rule}</td><td>{file_}:{line}</td><td>{commit}</td></tr>"""

    # ── SonarQube section ──────────────────────────────────────────────
    sonar_html = ""
    if sonar_data:
        sonar_html = f"""
        <h2>🔵 SonarQube</h2>
        <div class="badges-row">
            {badge(sonar_data.get("bugs","N/A"), "Bugs", "#c0392b")}
            {badge(sonar_data.get("vulnerabilities","N/A"), "Vulnérabilités", "#8e1a1a")}
            {badge(sonar_data.get("code_smells","N/A"), "Code Smells", "#e67e22")}
            {badge(sonar_data.get("security_hotspots","N/A"), "Hotspots", "#c0392b")}
            {badge(sonar_data.get("coverage","N/A") + "%", "Couverture", "#27ae60")}
        </div>"""

    # ── SBOM section ───────────────────────────────────────────────────
    sbom_html = ""
    if sbom_exists:
        sbom_path = r / "sbom/bom.json"
        sbom_raw  = load_json(sbom_path, {})
        comp_count = len(sbom_raw.get("components", []))
        sbom_html = f"""
        <h2>📦 SBOM — CycloneDX</h2>
        <div class="badges-row">
            {badge(comp_count, "Composants", "#2980b9")}
            {badge("✅", "bom.xml", "#27ae60")}
            {badge("✅", "bom.json", "#27ae60")}
        </div>"""

    # ── HTML ───────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Dashboard — {args.project}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px}}
    h1{{color:#00d4ff;font-size:1.8em;margin-bottom:6px}}
    h2{{color:#a0c4ff;font-size:1.1em;margin:28px 0 12px;border-left:4px solid #00d4ff;padding-left:10px}}
    .meta{{color:#aaa;font-size:13px;margin-bottom:24px}}
    .gate{{display:inline-block;padding:10px 28px;border-radius:6px;font-size:1.1em;
           font-weight:bold;color:#fff;background:{gate_color};margin-bottom:24px}}
    .badges-row{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}}
    .badge{{padding:14px 22px;border-radius:8px;color:#fff;text-align:center;min-width:90px}}
    .badge .num{{font-size:1.8em;font-weight:bold;line-height:1.1}}
    .badge .lbl{{font-size:11px;opacity:0.9;margin-top:4px}}
    .badge-inline{{padding:2px 8px;border-radius:4px;color:#fff;font-size:11px;font-weight:bold}}
    table{{width:100%;border-collapse:collapse;background:#16213e;border-radius:8px;
           overflow:hidden;margin-bottom:28px;font-size:13px}}
    th{{background:#0f3460;color:#a0c4ff;padding:10px;text-align:left}}
    td{{padding:9px 10px;border-bottom:1px solid #1e2a4a;vertical-align:top}}
    tr:hover{{background:#1e2a4a}}
    .ok{{color:#27ae60;font-weight:bold}}
    .warn{{color:#e67e22;font-weight:bold}}
    .danger{{color:#c0392b;font-weight:bold}}
    .section{{background:#16213e;border-radius:8px;padding:16px 20px;margin-bottom:20px}}
  </style>
</head>
<body>
  <h1>🛡️ Security Dashboard — {args.project}</h1>
  <div class="meta">Généré le {now}</div>

  <div class="gate">🚪 OPA Security Gate : {gate_label}</div>

  <h2>🔴 Gitleaks — Secrets détectés</h2>
  <div class="badges-row">
    {badge(gitleaks_count, "Secrets", "#8e1a1a" if gitleaks_count > 0 else "#27ae60")}
  </div>
  {"" if not gitleaks_rows else f"""
  <table><thead><tr><th>Sévérité</th><th>Règle</th><th>Fichier:Ligne</th><th>Commit</th></tr></thead>
  <tbody>{gitleaks_rows}</tbody></table>"""}

  <h2>🟠 Trivy — Vulnérabilités image</h2>
  <div class="badges-row">
    {badge(trivy_sev["CRITICAL"], "CRITICAL", "#8e1a1a")}
    {badge(trivy_sev["HIGH"],     "HIGH",     "#c0392b")}
    {badge(trivy_sev["MEDIUM"],   "MEDIUM",   "#e67e22")}
    {badge(trivy_sev["LOW"],      "LOW",      "#c8a200")}
  </div>
  {"" if not trivy_rows else f"""
  <table><thead><tr><th>Sévérité</th><th>CVE</th><th>Package</th>
  <th>Version</th><th>Fix</th><th>Titre</th></tr></thead>
  <tbody>{trivy_rows}</tbody></table>"""}

  <h2>🟡 OWASP ZAP — Scan DAST</h2>
  <div class="badges-row">
    {badge(zap_counts["3"], "HIGH",   "#c0392b")}
    {badge(zap_counts["2"], "MEDIUM", "#e67e22")}
    {badge(zap_counts["1"], "LOW",    "#c8a200")}
    {badge(zap_counts["0"], "INFO",   "#2980b9")}
  </div>
  {"" if not zap_rows else f"""
  <table><thead><tr><th>Risque</th><th>Alerte</th>
  <th>Description</th><th>Solution</th></tr></thead>
  <tbody>{zap_rows}</tbody></table>"""}

  {sonar_html}
  {sbom_html}

  <h2>📋 OPA Input Summary</h2>
  <div class="section"><pre style="font-size:13px;color:#a0ffa0">{json.dumps(opa_input, indent=2)}</pre></div>

</body>
</html>"""

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"✅ Dashboard généré : {out}")

if __name__ == "__main__":
    main()
PYDASH

                    # ── zap_to_html.py ──────────────────────────────────────
                    cat > reports/zap/zap_to_html.py <<'ZAPEOF'
import json
from pathlib import Path

src = Path("zap-report.json")
out = Path("zap-report.html")

try:
    data = json.loads(src.read_text(encoding="utf-8"))
except Exception:
    data = {"site": [{"alerts": []}]}

RISK_LABEL = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
RISK_COLOR = {"3": "#c0392b", "2": "#e67e22", "1": "#f1c40f", "0": "#2980b9"}

all_alerts = []
target = ""
for site in data.get("site", []) or []:
    if not target:
        target = site.get("@name", site.get("name", "N/A"))
    for alert in site.get("alerts", []) or []:
        all_alerts.append(alert)

all_alerts.sort(key=lambda a: -int(a.get("riskcode", 0)))

rows = ""
for a in all_alerts:
    rc   = str(a.get("riskcode", "0"))
    name = a.get("alert", a.get("name", "?"))
    desc = a.get("desc", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    sol  = a.get("solution", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    url  = next((i.get("uri", "") for i in a.get("instances", [])[:1]), "")
    color = RISK_COLOR.get(rc, "#999")
    label = RISK_LABEL.get(rc, rc)
    rows += f"""<tr>
  <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{label}</span></td>
  <td><strong>{name}</strong><br><small style="color:#555">{url}</small></td>
  <td style="font-size:12px">{desc}</td>
  <td style="font-size:12px">{sol}</td>
</tr>"""

counts = {"3": 0, "2": 0, "1": 0, "0": 0}
for a in all_alerts:
    rc = str(a.get("riskcode", "0"))
    if rc in counts:
        counts[rc] += 1

html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>ZAP Security Report</title>
  <style>
    body  {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
    h1    {{ color: #2c3e50; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
    .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
    .badge   {{ padding: 15px 25px; border-radius: 8px; color: #fff; text-align: center; min-width: 100px; }}
    .badge .num {{ font-size: 2em; font-weight: bold; }}
    .badge .lbl {{ font-size: 12px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,.1); }}
    th    {{ background: #2c3e50; color: #fff; padding: 10px; text-align: left; }}
    td    {{ padding: 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
    tr:hover {{ background: #fafafa; }}
    .meta {{ background: #fff; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.1); }}
  </style>
</head>
<body>
  <h1>ZAP Baseline Scan — Security Report</h1>
  <div class="meta">
    <strong>Cible :</strong> {target}<br>
    <strong>Total alertes :</strong> {len(all_alerts)}
  </div>
  <div class="summary">
    <div class="badge" style="background:#c0392b"><div class="num">{counts["3"]}</div><div class="lbl">HIGH</div></div>
    <div class="badge" style="background:#e67e22"><div class="num">{counts["2"]}</div><div class="lbl">MEDIUM</div></div>
    <div class="badge" style="background:#c8a200"><div class="num">{counts["1"]}</div><div class="lbl">LOW</div></div>
    <div class="badge" style="background:#2980b9"><div class="num">{counts["0"]}</div><div class="lbl">INFO</div></div>
  </div>
  <table>
    <thead><tr><th>Risque</th><th>Alerte</th><th>Description</th><th>Solution</th></tr></thead>
    <tbody>
      {rows if rows else '<tr><td colspan="4" style="text-align:center;padding:30px;color:#27ae60"><strong>Aucune alerte</strong></td></tr>'}
    </tbody>
  </table>
</body>
</html>"""

out.write_text(html, encoding="utf-8")
print("Rapport HTML ZAP généré : " + str(out))
ZAPEOF

                    # ── patch_csp.py ─────────────────────────────────────────
                    cat > reports/dashboard/patch_csp.py <<'PYEOF'
from pathlib import Path
import sys

META = """<meta http-equiv="Content-Security-Policy" content="default-src 'self' data: blob: https:; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:;">"""

def patch(path_str):
    p = Path(path_str)
    if not p.exists():
        print(f"[SKIP] Fichier absent : {p}")
        return
    html = p.read_text(encoding="utf-8", errors="ignore")
    if 'http-equiv="Content-Security-Policy"' in html:
        print(f"[OK] CSP déjà présente : {p}")
        return
    if "<head>" in html:
        html = html.replace("<head>", "<head>\n  " + META, 1)
    else:
        html = META + "\n" + html
    p.write_text(html, encoding="utf-8")
    print(f"[OK] CSP ajoutée : {p}")

for target in sys.argv[1:]:
    patch(target)
PYEOF

                    echo "✅ Workspace prepared"
                '''
            }
        }

        // ── 5. COMPILE LIGHT ────────────────────────────────────────────────
        stage('Compile Light') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== COMPILE LIGHT ==="

                    # Find pom.xml
                    if [ -f "$PROJECT_DIR/pom.xml" ]; then
                        POM_PATH="$PROJECT_DIR/pom.xml"
                        WORK_DIR="$PROJECT_DIR"
                    elif [ -f "$PROJECT_DIR/backend/pom.xml" ]; then
                        POM_PATH="$PROJECT_DIR/backend/pom.xml"
                        WORK_DIR="$PROJECT_DIR/backend"
                    else
                        echo "❌ pom.xml not found in $PROJECT_DIR or $PROJECT_DIR/backend"
                        find "$PROJECT_DIR" -name "pom.xml" -maxdepth 4 | head -5
                        exit 1
                    fi

                    echo "📦 Using POM: $POM_PATH"

                    docker run --rm \
                        --user "${JENKINS_UID}:${JENKINS_GID}" \
                        -v "$MAVEN_REPO:$MAVEN_REPO:rw" \
                        -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                        -w "$WORK_DIR" \
                        maven:3.9.9-eclipse-temurin-17 \
                        sh -lc "mvn -B -f '$POM_PATH' \
                                    -Dmaven.repo.local='$MAVEN_REPO' \
                                    clean compile -DskipTests"

                    echo "✅ Compile successful"
                '''
            }
        }

        // ── 6. SECURITY SCANS (parallel) ─────────────────────────────────────
        stage('Security Scans') {
            parallel {

                stage('Secrets - Gitleaks') {
                    options { timeout(time: 5, unit: 'MINUTES') }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                echo "=== GITLEAKS SCAN ==="

                                docker run --rm \
                                    -v "$PROJECT_DIR:$PROJECT_DIR:ro" \
                                    -w "$PROJECT_DIR" \
                                    zricethezav/gitleaks:latest detect \
                                        --source . \
                                        --log-opts="--all" \
                                        --report-format json \
                                        --report-path reports/gitleaks/gitleaks-report.json \
                                        --exit-code 0

                                test -s reports/gitleaks/gitleaks-report.json \
                                    || echo "[]" > reports/gitleaks/gitleaks-report.json

                                echo "✅ Gitleaks completed"
                            '''
                        }
                    }
                }

                stage('SCA - Trivy Image') {
                    options { timeout(time: 15, unit: 'MINUTES') }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                echo "=== TRIVY SCA SCAN ==="

                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$PROJECT_DIR/reports/trivy:/reports:rw" \
                                    -v "$TRIVY_CACHE:/root/.cache/trivy:rw" \
                                    ghcr.io/aquasecurity/trivy:latest image \
                                        --no-progress \
                                        --quiet \
                                        --scanners vuln \
                                        --severity CRITICAL,HIGH \
                                        --format json \
                                        --output /reports/trivy-report.json \
                                        "$DOCKER_IMAGE"

                                test -s reports/trivy/trivy-report.json \
                                    || echo '{"Results":[]}' > reports/trivy/trivy-report.json

                                echo "✅ Trivy completed"
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube Analysis') {
                    options { timeout(time: 20, unit: 'MINUTES') }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            script {
                                withSonarQubeEnv("${SONARQUBE_ENV}") {
                                    sh '''
                                        set -eu
                                        cd "$PROJECT_DIR"
                                        echo "=== SONARQUBE SAST ==="

                                        # Find target/classes (root or backend/)
                                        if [ -d "$PROJECT_DIR/target/classes" ]; then
                                            BINARIES="target/classes"
                                        elif [ -d "$PROJECT_DIR/backend/target/classes" ]; then
                                            BINARIES="backend/target/classes"
                                        else
                                            echo "⚠️  No compiled classes — skipping SonarQube"
                                            exit 0
                                        fi

                                        POM_PATH="$PROJECT_DIR/pom.xml"
                                        [ -f "$POM_PATH" ] || POM_PATH="$PROJECT_DIR/backend/pom.xml"

                                        docker run --rm \
                                            --user "${JENKINS_UID}:${JENKINS_GID}" \
                                            --network "$NETWORK_NAME" \
                                            --add-host=host.docker.internal:host-gateway \
                                            -v "$MAVEN_REPO:$MAVEN_REPO:rw" \
                                            -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                                            -w "$PROJECT_DIR" \
                                            -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                            -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                            maven:3.9.9-eclipse-temurin-17 \
                                            sh -lc "mvn -B -f '$POM_PATH' \
                                                        -Dmaven.repo.local='$MAVEN_REPO' \
                                                        org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                                        -Dsonar.projectKey='$APP_NAME' \
                                                        -Dsonar.host.url='$SONAR_HOST_URL' \
                                                        -Dsonar.token='$SONAR_AUTH_TOKEN' \
                                                        -Dsonar.java.binaries='$BINARIES'"

                                        echo "✅ SonarQube completed"
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    options { timeout(time: 10, unit: 'MINUTES') }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                echo "=== CYCLONEDX SBOM ==="

                                POM_PATH="$PROJECT_DIR/pom.xml"
                                [ -f "$POM_PATH" ] || POM_PATH="$PROJECT_DIR/backend/pom.xml"

                                docker run --rm \
                                    --user "${JENKINS_UID}:${JENKINS_GID}" \
                                    -v "$MAVEN_REPO:$MAVEN_REPO:rw" \
                                    -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                                    -w "$PROJECT_DIR" \
                                    maven:3.9.9-eclipse-temurin-17 \
                                    sh -lc "mvn -B -f '$POM_PATH' \
                                                -Dmaven.repo.local='$MAVEN_REPO' \
                                                org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                                                -DoutputFormat=all"

                                for BOM_DIR in "$PROJECT_DIR/target" "$PROJECT_DIR/backend/target"; do
                                    [ -f "$BOM_DIR/bom.xml"  ] && cp -f "$BOM_DIR/bom.xml"  "$PROJECT_DIR/reports/sbom/bom.xml"  || true
                                    [ -f "$BOM_DIR/bom.json" ] && cp -f "$BOM_DIR/bom.json" "$PROJECT_DIR/reports/sbom/bom.json" || true
                                done

                                echo "✅ CycloneDX SBOM completed"
                            '''
                        }
                    }
                }

            }
        }

        // ── 7. DEPLOY MYSQL ──────────────────────────────────────────────────
        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eu
                    echo "=== DEPLOY MYSQL ==="

                    docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                    docker run -d \
                        --name "$MYSQL_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        -e MYSQL_ROOT_PASSWORD=root \
                        -e MYSQL_DATABASE=archivage_doc \
                        -e MYSQL_USER=archivage_user \
                        -e MYSQL_PASSWORD=archivage_pass \
                        mysql:8.0 >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        if docker run --rm --network "$NETWORK_NAME" mysql:8.0 \
                                mysqladmin ping -h"$MYSQL_CONTAINER" -uroot -proot --silent 2>/dev/null; then
                            READY=1
                            echo "✅ MySQL ready (attempt $i/30)"
                            break
                        fi
                        echo "⏳ Waiting for MySQL... ($i/30)"
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "❌ MySQL not ready after 150s"
                        docker logs "$MYSQL_CONTAINER" --tail 50 || true
                        exit 1
                    fi

                    echo "✅ MySQL deployment successful"
                '''
            }
        }

        // ── 8. DEPLOY APP ────────────────────────────────────────────────────
        stage('Deploy App') {
            steps {
                sh '''
                    set -eu
                    echo "=== DEPLOY APP ==="

                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                    mkdir -p "$PROJECT_DIR/uploads"
                    chmod 755 "$PROJECT_DIR/uploads"

                    docker run -d \
                        --name "$APP_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        --restart on-failure:5 \
                        -v "$PROJECT_DIR/uploads:/app/uploads" \
                        -e SPRING_PROFILES_ACTIVE=docker \
                        -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" \
                        -e SPRING_DATASOURCE_USERNAME="archivage_user" \
                        -e SPRING_DATASOURCE_PASSWORD="archivage_pass" \
                        -e GITHUB_OAUTH_SECRET="${GITHUB_OAUTH_SECRET:-test}" \
                        -e JWT_SECRET="${JWT_SECRET:-test}" \
                        "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 36); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                               -s -o /dev/null -w "%{http_code}" \
                               "http://$APP_CONTAINER:$APP_PORT/actuator/health" 2>/dev/null || echo "000")

                        if echo "$CODE" | grep -qE "^(200|302)$"; then
                            READY=1
                            echo "✅ App ready (HTTP $CODE, attempt $i/36)"
                            break
                        fi

                        echo "⏳ Waiting for app... (HTTP $CODE, attempt $i/36)"
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "❌ App not ready after 180s"
                        docker logs "$APP_CONTAINER" --tail 100 || true
                        exit 1
                    fi

                    echo "✅ App deployment successful"
                '''
            }
        }

        // ── 9. DAST - OWASP ZAP ─────────────────────────────────────────────
        stage('DAST - OWASP ZAP') {
            options { timeout(time: 30, unit: 'MINUTES') }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eu
                        cd "$PROJECT_DIR"
                        echo "=== OWASP ZAP DAST ==="

                        mkdir -p "$PROJECT_DIR/reports/zap"
                        chmod 777 "$PROJECT_DIR/reports/zap"

                        docker run --rm \
                            --network "$NETWORK_NAME" \
                            -v "$PROJECT_DIR/reports/zap:/zap/wrk:rw" \
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                                -t "http://$APP_CONTAINER:$APP_PORT/" \
                                -J "zap-report.json" \
                                -a -j -I || true

                        docker run --rm \
                            -u 0:0 \
                            -v "$PROJECT_DIR/reports/zap:/zap/wrk" \
                            alpine:3.19 \
                            sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /zap/wrk && chmod -R u+w /zap/wrk" || true

                        test -s "$PROJECT_DIR/reports/zap/zap-report.json" \
                            || echo '{"site":[{"alerts":[]}]}' > "$PROJECT_DIR/reports/zap/zap-report.json"

                        docker run --rm \
                            -v "$PROJECT_DIR/reports/zap:$PROJECT_DIR/reports/zap:rw" \
                            -w "$PROJECT_DIR/reports/zap" \
                            python:3.12-alpine \
                            python zap_to_html.py

                        echo "✅ ZAP scan completed"
                    '''
                }
            }
        }

        // ── 10. POLICY - OPA SECURITY GATE ──────────────────────────────────
        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== OPA SECURITY GATE ==="

                    docker run --rm \
                        -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                        -w "$PROJECT_DIR" \
                        python:3.12-alpine \
                        python - <<'PYEOF'
import json
import sys
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] {path}: {e}", file=sys.stderr)
        return default

gitleaks = load_json("reports/gitleaks/gitleaks-report.json", [])
trivy    = load_json("reports/trivy/trivy-report.json", {"Results": []})
zap      = load_json("reports/zap/zap-report.json", {"site": [{"alerts": []}]})

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in trivy.get("Results", []) or []:
    for v in result.get("Vulnerabilities", []) or []:
        s = (v.get("Severity") or "").upper()
        if s in sev:
            sev[s] += 1

zap_high = 0
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        if str(alert.get("riskcode", 0)) == "3":
            zap_high += 1

payload = {
    "gitleaks": gitleaks if isinstance(gitleaks, list) else [],
    "trivy": {"critical": sev["CRITICAL"], "high": sev["HIGH"],
              "medium": sev["MEDIUM"], "low": sev["LOW"]},
    "zap": {"high": zap_high}
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

print("=== OPA INPUT SUMMARY ===")
print(f"  Gitleaks secrets : {len(payload['gitleaks'])}")
print(f"  Trivy CRITICAL   : {sev['CRITICAL']}")
print(f"  Trivy HIGH       : {sev['HIGH']}")
print(f"  ZAP HIGH         : {zap_high}")
print("=========================")
PYEOF

                    docker run --rm \
                        -v "$PROJECT_DIR:$PROJECT_DIR:ro" \
                        -w "$PROJECT_DIR" \
                        openpolicyagent/opa:latest \
                        eval \
                            --format raw \
                            --data "$PROJECT_DIR/policy/security-gate.rego" \
                            --input "$PROJECT_DIR/reports/opa/input.json" \
                            "data.security.allow" \
                        > "$PROJECT_DIR/reports/opa/opa-result.txt"

                    OPA_RESULT=$(cat "$PROJECT_DIR/reports/opa/opa-result.txt")
                    echo "🚪 OPA Security Gate Result: $OPA_RESULT"

                    if [ "$OPA_RESULT" != "true" ]; then
                        echo "❌ SECURITY GATE BLOCKED"
                        exit 1
                    fi

                    echo "✅ OPA Security Gate PASSED"
                '''
            }
        }
    }

    post {

        always {
            echo "=== CLEANUP & REPORTING PHASE ==="

            sh '''
                set +e
                docker run --rm -u 0:0 \
                    -v "$WORKSPACE:/ws" \
                    alpine:3.19 \
                    sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null || true"
                echo "✅ Permissions fixed"
            '''

            // ── Dashboard consolidé ──────────────────────────────────────
            script {
                if (fileExists('src/generate_dashboard.py')) {
                    withSonarQubeEnv("${SONARQUBE_ENV}") {
                        sh '''
                            set +e
                            cd "$PROJECT_DIR"
                            mkdir -p reports/dashboard
                            docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 \
                                || docker network create "$NETWORK_NAME" >/dev/null 2>&1 || true

                            docker run --rm \
                                --network "$NETWORK_NAME" \
                                --add-host=host.docker.internal:host-gateway \
                                -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                                -w "$PROJECT_DIR" \
                                -e SONAR_HOST_URL="${SONAR_HOST_URL:-}" \
                                -e SONAR_AUTH_TOKEN="${SONAR_AUTH_TOKEN:-}" \
                                python:3.12-alpine \
                                python generate_dashboard.py \
                                    --reports reports \
                                    --output reports/dashboard/security-dashboard.html \
                                    --project "$APP_NAME" \
                                    --sonar-url "${SONAR_HOST_URL:-}" \
                                    --sonar-token "${SONAR_AUTH_TOKEN:-}" \
                                    --sonar-project "$APP_NAME" || true
                        '''
                    }
                } else {
                    echo '⚠️  generate_dashboard.py absent — dashboard skipped'
                }
            }

            // ── Patch CSP ────────────────────────────────────────────────
            script {
                if (fileExists('src/reports/dashboard/patch_csp.py')) {
                    sh '''
                        set +e
                        cd "$PROJECT_DIR"
                        docker run --rm \
                            -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                            -w "$PROJECT_DIR" \
                            python:3.12-alpine \
                            python reports/dashboard/patch_csp.py \
                                reports/dashboard/security-dashboard.html \
                                reports/zap/zap-report.html || true
                    '''
                }
            }

            // ── Publish Security Dashboard ───────────────────────────────
            script {
                if (fileExists('src/reports/dashboard/security-dashboard.html')) {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'src/reports/dashboard',
                        reportFiles          : 'security-dashboard.html',
                        reportName           : 'Security Dashboard'
                    ])
                }
            }

            // ── Publish ZAP report ───────────────────────────────────────
            script {
                if (fileExists('src/reports/zap/zap-report.html')) {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : false,
                        reportDir            : 'src/reports/zap',
                        reportFiles          : 'zap-report.html',
                        reportName           : 'ZAP Web Report'
                    ])
                }
            }

            // ── Trivy warnings ───────────────────────────────────────────
            script {
                if (fileExists('src/reports/trivy/trivy-report.json')) {
                    recordIssues(
                        enabledForFailure: true,
                        aggregatingResults: true,
                        tools: [
                            trivy(
                                pattern: 'src/reports/trivy/trivy-report.json',
                                reportEncoding: 'UTF-8'
                            )
                        ]
                    )
                }
            }

            // ── Archive artifacts ────────────────────────────────────────
            script {
                if (fileExists('src/reports')) {
                    archiveArtifacts(
                        artifacts: [
                            'src/reports/gitleaks/gitleaks-report.json',
                            'src/reports/trivy/trivy-report.json',
                            'src/reports/zap/zap-report.html',
                            'src/reports/zap/zap-report.json',
                            'src/reports/opa/opa-result.txt',
                            'src/reports/opa/input.json',
                            'src/reports/sbom/bom.json',
                            'src/reports/sbom/bom.xml',
                            'src/reports/dashboard/security-dashboard.html'
                        ].join(','),
                        allowEmptyArchive: true,
                        fingerprint      : false
                    )
                }
            }

            // ── Cleanup containers ───────────────────────────────────────
            sh '''
                set +e
                docker logout >/dev/null 2>&1 || true
                docker rm -f "$APP_CONTAINER"   >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
                echo "✅ Cleanup completed"
            '''
        }

        failure {
            echo '❌ Pipeline FAILED — Check logs and security reports'
        }

        unstable {
            echo '⚠️  Pipeline UNSTABLE — Security issues detected'
        }

        success {
            echo '✅ Pipeline SUCCESS — All security gates passed'
        }
    }
}
