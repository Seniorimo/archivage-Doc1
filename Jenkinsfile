pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        APP_NAME        = 'archivage-Doc'
        APP_CONTAINER   = 'app-archivage'
        MYSQL_CONTAINER = 'mysql-archivage'
        NETWORK_NAME    = 'archivage-net'
        APP_PORT        = '8090'
        PROJECT_DIR     = "${WORKSPACE}/src"
        DOCKER_IMAGE    = "archivage-app:${env.BUILD_NUMBER}"
        MAVEN_REPO      = '/var/jenkins_home/.m2/repository'
        TRIVY_CACHE     = "${WORKSPACE}/src/.trivycache"
        SONARQUBE_ENV   = 'sonar'
        SONAR_DOCKER_URL = 'http://host.docker.internal:9000'
        JENKINS_UID     = """${sh(returnStdout: true, script: 'id -u').trim()}"""
        JENKINS_GID     = """${sh(returnStdout: true, script: 'id -g').trim()}"""
    }

    stages {

        stage('Force Clean Workspace') {
            steps {
                sh '''
                    set -eux

                    echo "=== FORCE CLEAN WORKSPACE ==="
                    docker run --rm \
                      -u 0:0 \
                      -v "$WORKSPACE:/ws" \
                      alpine:3.19 \
                      sh -euxc "
                        find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
                        mkdir -p /ws/src
                        chown -R ${JENKINS_UID}:${JENKINS_GID} /ws
                        ls -la /ws
                      "

                    echo "Workspace nettoye de force avec succes."
                '''
            }
        }

        stage('Checkout') {
            steps {
                dir('src') {
                    deleteDir()
                    checkout scm
                }
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu

                    cd "$PROJECT_DIR"

                    echo "=== PREPARE WORKSPACE ==="
                    rm -rf reports .trivycache policy .jarpath
                    mkdir -p \
                      reports/gitleaks \
                      reports/trivy \
                      reports/sbom \
                      reports/zap \
                      reports/opa \
                      reports/sonar \
                      .trivycache \
                      policy

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"

                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

allow if {
    input.trivy.blocking.critical == 0
    input.trivy.blocking.high == 0
    input.gitleaks.blocking_count == 0
    input.zap.blocking.high == 0
}
REGO

                    cat > reports/gitleaks/print_gitleaks_summary.py <<'PYEOF'
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/gitleaks/gitleaks-report.json")

try:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        data = []
except Exception:
    data = []

print("=== GITLEAKS SUMMARY ===")
print(f"Total leaks detectes : {len(data)}")

if not data:
    print("Aucun secret detecte.")
    sys.exit(0)

for i, leak in enumerate(data[:20], 1):
    rule = leak.get("RuleID", "?")
    file = leak.get("File", "?")
    line = leak.get("StartLine", leak.get("Line", "?"))
    commit = str(leak.get("Commit", "?"))[:12]
    desc = leak.get("Description", "") or leak.get("RuleDescription", "")
    print(f"[{i}] Rule={rule} | File={file} | Line={line} | Commit={commit}")
    if desc:
        print(f"    Desc={desc}")

if len(data) > 20:
    print(f"... {len(data) - 20} autres secrets non affiches.")
PYEOF

                    cat > reports/trivy/print_trivy_summary.py <<'PYEOF'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/trivy/trivy-report.json")

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    data = {"Results": []}

severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
items = []

for result in data.get("Results", []) or []:
    target = result.get("Target", "?")
    for v in result.get("Vulnerabilities", []) or []:
        sev = (v.get("Severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
        items.append({
            "severity": sev,
            "id": v.get("VulnerabilityID", "?"),
            "pkg": v.get("PkgName", "?"),
            "installed": v.get("InstalledVersion", "?"),
            "fixed": v.get("FixedVersion", "N/A"),
            "title": v.get("Title", "") or "",
            "target": target
        })

items.sort(key=lambda x: (severity_order.get(x["severity"], 99), x["pkg"], x["id"]))

print("=== TRIVY SUMMARY ===")
print(f"CRITICAL={counts.get('CRITICAL', 0)} | HIGH={counts.get('HIGH', 0)} | MEDIUM={counts.get('MEDIUM', 0)} | LOW={counts.get('LOW', 0)} | UNKNOWN={counts.get('UNKNOWN', 0)}")

if not items:
    print("Aucune vulnerabilite detectee.")
    sys.exit(0)

for i, item in enumerate(items[:25], 1):
    print(f"[{i}] {item['severity']} | {item['id']} | {item['pkg']} | installed={item['installed']} | fix={item['fixed']}")
    print(f"    target={item['target']}")
    if item["title"]:
        print(f"    title={item['title']}")

if len(items) > 25:
    print(f"... {len(items) - 25} autres vulnerabilites non affichees.")
PYEOF

                    cat > reports/sonar/print_sonar_summary.py <<'PYEOF'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/sonar/sonar-vulnerabilities.json")

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    data = {"issues": [], "total": 0}

issues = data.get("issues", []) or []
counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}

for issue in issues:
    sev = (issue.get("severity") or "INFO").upper()
    counts[sev] = counts.get(sev, 0) + 1

print("=== SONARQUBE SECURITY SUMMARY ===")
print(f"Total vulnerabilities remontees : {data.get('total', len(issues))}")
print(f"BLOCKER={counts.get('BLOCKER', 0)} | CRITICAL={counts.get('CRITICAL', 0)} | MAJOR={counts.get('MAJOR', 0)} | MINOR={counts.get('MINOR', 0)} | INFO={counts.get('INFO', 0)}")

if not issues:
    print("Aucune vulnerabilite applicative remontee par l'API SonarQube.")
    sys.exit(0)

for i, issue in enumerate(issues[:20], 1):
    sev = issue.get("severity", "?")
    rule = issue.get("rule", "?")
    component = issue.get("component", "?")
    line = issue.get("line", "?")
    message = issue.get("message", "?")
    print(f"[{i}] {sev} | {rule} | {component}:{line}")
    print(f"    {message}")

if len(issues) > 20:
    print(f"... {len(issues) - 20} autres vulnerabilities non affichees.")
PYEOF

                    cat > reports/zap/print_zap_summary.py <<'PYEOF'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/zap/zap-report.json")

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    data = {"site": [{"alerts": []}]}

risk_label = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
counts = {"3": 0, "2": 0, "1": 0, "0": 0}
alerts = []

for site in data.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        rc = str(alert.get("riskcode", "0"))
        counts[rc] = counts.get(rc, 0) + 1
        first_uri = ""
        for inst in alert.get("instances", [])[:1]:
            first_uri = inst.get("uri", "")
        alerts.append({
            "riskcode": rc,
            "label": risk_label.get(rc, rc),
            "name": alert.get("alert", alert.get("name", "?")),
            "uri": first_uri,
            "solution": (alert.get("solution", "") or "").strip()
        })

alerts.sort(key=lambda x: -int(x["riskcode"]))

print("=== ZAP SUMMARY ===")
print(f"HIGH={counts.get('3', 0)} | MEDIUM={counts.get('2', 0)} | LOW={counts.get('1', 0)} | INFO={counts.get('0', 0)}")

if not alerts:
    print("Aucune alerte ZAP detectee.")
    sys.exit(0)

for i, a in enumerate(alerts[:20], 1):
    print(f"[{i}] {a['label']} | {a['name']}")
    if a["uri"]:
        print(f"    uri={a['uri']}")
    if a["solution"]:
        print(f"    solution={a['solution'][:250]}")

if len(alerts) > 20:
    print(f"... {len(alerts) - 20} autres alertes non affichees.")
PYEOF

                    cat > reports/opa/build_input.py <<'PYEOF'
import json
import sys
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

gitleaks = load_json("reports/gitleaks/gitleaks-report.json", [])
trivy    = load_json("reports/trivy/trivy-report.json", {"Results": []})
zap      = load_json("reports/zap/zap-report.json", {"site": [{"alerts": []}]})
sonar    = load_json("reports/sonar/sonar-vulnerabilities.json", {"issues": [], "total": 0})

def norm_path(value):
    return str(value or "").replace("\\\\", "/")

EXPECTED_GITLEAKS_FILE = "src/main/resources/application.properties"
EXPECTED_GITLEAKS_MARKER = "INTENTIONAL VULN - GITLEAKS TEST"
EXPECTED_GITLEAKS_PROPERTIES = {
    "aws.access.key",
    "aws.secret.key",
    "github.token",
    "stripe.api.key",
}
EXPECTED_GITLEAKS_RULES = {
    "aws-access-token",
    "aws-secret-access-key",
    "github-pat",
    "github-fine-grained-pat",
    "github-oauth",
    "stripe-access-token",
    "stripe-api-key",
    "generic-api-key",
}

EXPECTED_TRIVY_PACKAGES = {
    ("commons-collections", "3.2.1"),
    ("commons-text", "1.9"),
    ("log4j-core", "2.14.1"),
}

EXPECTED_ZAP_PATH_PREFIXES = (
    "/api/test",
)

def expected_gitleaks_lines():
    path = Path(EXPECTED_GITLEAKS_FILE)
    if not path.exists():
        return {}

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    marker_index = None
    for index, line in enumerate(lines):
        if EXPECTED_GITLEAKS_MARKER in line:
            marker_index = index
            break

    if marker_index is None:
        return {}

    expected = {}
    for index in range(marker_index + 1, len(lines)):
        stripped = lines[index].strip()
        if not stripped:
            break
        if stripped.startswith("#") and EXPECTED_GITLEAKS_MARKER not in stripped:
            break
        key = stripped.split("=", 1)[0].strip()
        if key in EXPECTED_GITLEAKS_PROPERTIES:
            expected[index + 1] = key

    return expected

EXPECTED_GITLEAKS_LINES = expected_gitleaks_lines()

def expected_gitleaks(leak):
    file_name = norm_path(leak.get("File"))
    rule = str(leak.get("RuleID", ""))
    line = leak.get("StartLine", leak.get("Line", 0))
    try:
        line = int(line)
    except Exception:
        line = 0
    return (
        file_name.endswith(EXPECTED_GITLEAKS_FILE)
        and rule in EXPECTED_GITLEAKS_RULES
        and line in EXPECTED_GITLEAKS_LINES
    )

def expected_trivy(vuln):
    pkg = str(vuln.get("PkgName", ""))
    installed = str(vuln.get("InstalledVersion", ""))
    return (pkg, installed) in EXPECTED_TRIVY_PACKAGES

def expected_zap(alert):
    if str(alert.get("riskcode", "")).strip() != "3":
        return False
    for inst in alert.get("instances", []) or []:
        uri = str(inst.get("uri", ""))
        parsed = urlparse(uri)
        path = parsed.path or uri
        if any(path == prefix or path.startswith(prefix + "/") for prefix in EXPECTED_ZAP_PATH_PREFIXES):
            return True
    return False

gitleaks_all = gitleaks if isinstance(gitleaks, list) else []
gitleaks_expected = [leak for leak in gitleaks_all if expected_gitleaks(leak)]
gitleaks_blocking = [leak for leak in gitleaks_all if not expected_gitleaks(leak)]

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
blocking_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
trivy_expected = []
trivy_blocking = []
for result in trivy.get("Results", []) or []:
    for v in result.get("Vulnerabilities", []) or []:
        s = (v.get("Severity") or "").upper()
        if s in sev:
            sev[s] += 1
            if expected_trivy(v):
                trivy_expected.append({
                    "id": v.get("VulnerabilityID", "?"),
                    "pkg": v.get("PkgName", "?"),
                    "installed": v.get("InstalledVersion", "?"),
                    "severity": s
                })
            else:
                blocking_sev[s] += 1
                trivy_blocking.append({
                    "id": v.get("VulnerabilityID", "?"),
                    "pkg": v.get("PkgName", "?"),
                    "installed": v.get("InstalledVersion", "?"),
                    "severity": s
                })

zap_high = 0
zap_blocking_high = 0
zap_expected_high = 0
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        if str(alert.get("riskcode", "")).strip() == "3":
            zap_high += 1
            if expected_zap(alert):
                zap_expected_high += 1
            else:
                zap_blocking_high += 1

sonar_counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
for issue in sonar.get("issues", []) or []:
    s = (issue.get("severity") or "INFO").upper()
    sonar_counts[s] = sonar_counts.get(s, 0) + 1

payload = {
    "gitleaks": {
        "total": len(gitleaks_all),
        "expected_count": len(gitleaks_expected),
        "blocking_count": len(gitleaks_blocking),
        "expected": gitleaks_expected,
        "blocking": gitleaks_blocking
    },
    "trivy": {
        "total": {
            "critical": sev["CRITICAL"],
            "high":     sev["HIGH"],
            "medium":   sev["MEDIUM"],
            "low":      sev["LOW"]
        },
        "expected": {
            "critical": sum(1 for item in trivy_expected if item["severity"] == "CRITICAL"),
            "high":     sum(1 for item in trivy_expected if item["severity"] == "HIGH"),
            "items":    trivy_expected
        },
        "blocking": {
            "critical": blocking_sev["CRITICAL"],
            "high":     blocking_sev["HIGH"],
            "medium":   blocking_sev["MEDIUM"],
            "low":      blocking_sev["LOW"],
            "items":    trivy_blocking
        }
    },
    "zap": {
        "total": {"high": zap_high},
        "expected": {"high": zap_expected_high},
        "blocking": {"high": zap_blocking_high}
    },
    "sonar": {
        "blocker": sonar_counts["BLOCKER"],
        "critical": sonar_counts["CRITICAL"],
        "major": sonar_counts["MAJOR"],
        "minor": sonar_counts["MINOR"],
        "info": sonar_counts["INFO"]
    }
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

print("=== OPA INPUT SUMMARY ===")
print("  Gitleaks total / expected / blocking : "
      + str(payload["gitleaks"]["total"]) + " / "
      + str(payload["gitleaks"]["expected_count"]) + " / "
      + str(payload["gitleaks"]["blocking_count"]))
print("  Trivy CRITICAL total / expected / blocking : "
      + str(sev["CRITICAL"]) + " / "
      + str(payload["trivy"]["expected"]["critical"]) + " / "
      + str(payload["trivy"]["blocking"]["critical"]))
print("  Trivy HIGH total / expected / blocking     : "
      + str(sev["HIGH"]) + " / "
      + str(payload["trivy"]["expected"]["high"]) + " / "
      + str(payload["trivy"]["blocking"]["high"]))
print("  ZAP HIGH total / expected / blocking       : "
      + str(zap_high) + " / "
      + str(zap_expected_high) + " / "
      + str(zap_blocking_high))
print("  Sonar BLOCKER    : " + str(payload["sonar"]["blocker"]))
print("  Sonar CRITICAL   : " + str(payload["sonar"]["critical"]))
print("  Sonar MAJOR      : " + str(payload["sonar"]["major"]))
print("=========================")

if trivy_expected:
    print("[DETAIL] CVE Trivy attendues pour tests volontaires :")
    for item in trivy_expected[:20]:
        print("  " + item["severity"]
              + "  " + item["id"]
              + "  " + item["pkg"]
              + "  " + item["installed"])

if trivy_blocking:
    print("[DETAIL] CVE Trivy bloquantes non attendues :")
    for item in trivy_blocking[:20]:
        print("  " + item["severity"]
              + "  " + item["id"]
              + "  " + item["pkg"]
              + "  " + item["installed"])

if len(gitleaks_all) > 0:
    print("[DETAIL] Secrets Gitleaks detectes :")
    for leak in gitleaks_all[:10]:
        status = "EXPECTED" if expected_gitleaks(leak) else "BLOCKING"
        print("  Rule: " + str(leak.get("RuleID", "?"))
              + "  File: " + str(leak.get("File", "?"))
              + "  Commit: " + str(leak.get("Commit", "?"))[:8]
              + "  Status: " + status)

if payload["sonar"]["blocker"] > 0 or payload["sonar"]["critical"] > 0 or payload["sonar"]["major"] > 0:
    print("[DETAIL] Sonar vulnerabilities :")
    for issue in sonar.get("issues", [])[:10]:
        print("  " + str(issue.get("severity", "?"))
              + "  " + str(issue.get("rule", "?"))
              + "  " + str(issue.get("component", "?"))
              + "  " + str(issue.get("message", "?")))

sys.exit(0)
PYEOF

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

all_alerts.sort(key=lambda a: -int(str(a.get("riskcode", "0"))))

rows = ""
for a in all_alerts:
    rc   = str(a.get("riskcode", "0"))
    name = a.get("alert", a.get("name", "?"))
    desc = a.get("desc", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    sol  = a.get("solution", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    url  = ""
    for inst in a.get("instances", [])[:1]:
        url = inst.get("uri", "")
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
  body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
  h1 {{ color: #2c3e50; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
  .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
  .badge {{ padding: 15px 25px; border-radius: 8px; color: #fff; text-align: center; min-width: 100px; }}
  .badge .num {{ font-size: 2em; font-weight: bold; }}
  .badge .lbl {{ font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
  th {{ background: #2c3e50; color: #fff; padding: 10px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover {{ background: #fafafa; }}
  .meta {{ background: #fff; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
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
  <tbody>{rows if rows else '<tr><td colspan="4" style="text-align:center;padding:30px;color:#27ae60"><strong>Aucune alerte detectee</strong></td></tr>'}</tbody>
</table>
</body>
</html>"""

out.write_text(html, encoding="utf-8")
print("Rapport HTML ZAP genere : " + str(out))
ZAPEOF

                    echo "Workspace prepare avec succes."
                '''
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"

                    echo "=== BUILD & PACKAGE ==="
                    echo "[1/3] Compilation Maven..."
                    docker run --rm \
                      --user "${JENKINS_UID}:${JENKINS_GID}" \
                      --volumes-from jenkins \
                      -w "$PROJECT_DIR" \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' clean package -DskipTests"

                    echo "[2/3] Verification du JAR genere..."
                    JARPATH=$(find "$PROJECT_DIR/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    test -n "$JARPATH"
                    test -f "$JARPATH"
                    echo "$JARPATH" > "$PROJECT_DIR/.jarpath"
                    echo "JAR detecte : $(basename "$JARPATH")"

                    echo "[3/3] Build image Docker..."
                    docker build -t "$DOCKER_IMAGE" "$PROJECT_DIR"
                    echo "Image Docker construite : $DOCKER_IMAGE"
                '''
            }
        }

        stage('Security Scans') {
            parallel {
                stage('Secrets - Gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"

                                echo "=== GITLEAKS ==="
                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$PROJECT_DIR" \
                                  zricethezav/gitleaks:latest detect \
                                  --source . \
                                  --log-opts="--all" \
                                  --report-format json \
                                  --report-path reports/gitleaks/gitleaks-report.json \
                                  --exit-code 0

                                test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json

                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$PROJECT_DIR" \
                                  python:3.12-alpine \
                                  python reports/gitleaks/print_gitleaks_summary.py reports/gitleaks/gitleaks-report.json

                                echo "Rapport Gitleaks disponible : reports/gitleaks/gitleaks-report.json"
                            '''
                        }
                    }
                }

                stage('Trivy FS Scan') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"

                                echo "=== TRIVY FS ==="
                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$PROJECT_DIR" \
                                  -v "$TRIVY_CACHE:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs \
                                  --no-progress \
                                  --quiet \
                                  --scanners vuln \
                                  --severity CRITICAL,HIGH \
                                  --format json \
                                  --output reports/trivy/trivy-report.json .

                                test -s reports/trivy/trivy-report.json || echo '{"Results":[]}' > reports/trivy/trivy-report.json

                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$PROJECT_DIR" \
                                  python:3.12-alpine \
                                  python reports/trivy/print_trivy_summary.py reports/trivy/trivy-report.json

                                echo "Rapport Trivy disponible : reports/trivy/trivy-report.json"
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                                withSonarQubeEnv("${SONARQUBE_ENV}") {
                                    sh '''
                                        set -eu
                                        cd "$PROJECT_DIR"

                                        JARPATH=$(cat "$PROJECT_DIR/.jarpath" 2>/dev/null || echo "")
                                        test -n "$JARPATH"
                                        test -f "$JARPATH"
                                        test -d "$PROJECT_DIR/target/classes"

                                        echo "=== SONARQUBE ANALYSIS ==="
                                        docker run --rm \
                                          --user "${JENKINS_UID}:${JENKINS_GID}" \
                                          --network "$NETWORK_NAME" \
                                          --volumes-from jenkins \
                                          --add-host=host.docker.internal:host-gateway \
                                          -e SONAR_HOST_URL="$SONAR_DOCKER_URL" \
                                          -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                          -w "$PROJECT_DIR" \
                                          maven:3.9.9-eclipse-temurin-17 \
                                          sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                            -Dmaven.repo.local='$MAVEN_REPO' \
                                            org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                            -DskipTests \
                                            -Dsonar.projectKey='$APP_NAME' \
                                            -Dsonar.host.url='$SONAR_DOCKER_URL' \
                                            -Dsonar.login='$SONAR_AUTH_TOKEN' \
                                            -Dsonar.java.binaries='target/classes' \
                                            -Dsonar.qualitygate.wait=false"

                                        echo "=== SONARQUBE API EXPORT ==="
                                        docker run --rm \
                                          --user "${JENKINS_UID}:${JENKINS_GID}" \
                                          --network "$NETWORK_NAME" \
                                          --add-host=host.docker.internal:host-gateway \
                                          -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                          -e APP_NAME="$APP_NAME" \
                                          -e SONAR_DOCKER_URL="$SONAR_DOCKER_URL" \
                                          -v "$PROJECT_DIR/reports/sonar:/out" \
                                          curlimages/curl:8.7.1 \
                                          sh -lc '
                                            curl -sf -u "$SONAR_AUTH_TOKEN:" \
                                              "$SONAR_DOCKER_URL/api/issues/search?componentKeys=$APP_NAME&types=VULNERABILITY&severities=BLOCKER,CRITICAL,MAJOR,MINOR,INFO&p=1&ps=100" \
                                              -o /out/sonar-vulnerabilities.json || echo "{\"issues\":[],\"total\":0}" > /out/sonar-vulnerabilities.json
                                          '

                                        test -s reports/sonar/sonar-vulnerabilities.json || echo '{"issues":[],"total":0}' > reports/sonar/sonar-vulnerabilities.json

                                        docker run --rm \
                                          --volumes-from jenkins \
                                          -w "$PROJECT_DIR" \
                                          python:3.12-alpine \
                                          python reports/sonar/print_sonar_summary.py reports/sonar/sonar-vulnerabilities.json

                                        echo "Rapport SonarQube disponible : reports/sonar/sonar-vulnerabilities.json"
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"

                                echo "=== CYCLONEDX SBOM ==="
                                docker run --rm \
                                  --user "${JENKINS_UID}:${JENKINS_GID}" \
                                  --volumes-from jenkins \
                                  -w "$PROJECT_DIR" \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all"

                                test -f "$PROJECT_DIR/target/bom.xml" && cp -f "$PROJECT_DIR/target/bom.xml" "$PROJECT_DIR/reports/sbom/bom.xml"
                                test -f "$PROJECT_DIR/target/bom.json" && cp -f "$PROJECT_DIR/target/bom.json" "$PROJECT_DIR/reports/sbom/bom.json"
                                test -s reports/sbom/bom.json
                                echo "SBOM genere : reports/sbom/bom.xml + reports/sbom/bom.json"
                            '''
                        }
                    }
                }
            }
        }

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
                        mysqladmin ping -h"$MYSQL_CONTAINER" -uroot -proot --silent; then
                        READY=1
                        break
                      fi
                      echo "Waiting for MySQL ($i/30)..."
                      sleep 5
                    done

                    test "$READY" -eq 1
                    echo "MySQL pret. Pause 10s..."
                    sleep 10
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    set -eu

                    echo "=== DEPLOY APP ==="
                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                    mkdir -p "$PROJECT_DIR/uploads"

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$NETWORK_NAME" \
                      --restart on-failure:5 \
                      -v "$PROJECT_DIR/uploads:/app/uploads" \
                      -e SPRING_PROFILES_ACTIVE=docker \
                      -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" \
                      -e SPRING_DATASOURCE_USERNAME="archivage_user" \
                      -e SPRING_DATASOURCE_PASSWORD="archivage_pass" \
                      -e GITHUB_OAUTH_SECRET="test-secret" \
                      -e JWT_SECRET="404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970" \
                      "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                      CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)

                      if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then
                        READY=1
                        echo "Application repond avec HTTP $CODE"
                        break
                      fi

                      echo "Waiting for app health ($i/30)..."
                      docker ps -a --filter "name=$APP_CONTAINER" --format 'table {{.Names}}\\t{{.Status}}' || true
                      sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                      echo "============================================================"
                      echo "CRASH APPLICATIF DETECTE"
                      echo "============================================================"
                      docker logs "$APP_CONTAINER" --tail 200 || true
                      exit 1
                    fi
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eu
                        cd "$PROJECT_DIR"

                        echo "=== ZAP BASELINE ==="
                        mkdir -p "$PROJECT_DIR/reports/zap"
                        chmod 777 "$PROJECT_DIR/reports/zap"

                        docker run --rm \
                          --user root \
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
                          sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /zap/wrk || true"

                        test -s "$PROJECT_DIR/reports/zap/zap-report.json" \
                          || echo '{"site":[{"alerts":[]}]}' > "$PROJECT_DIR/reports/zap/zap-report.json"

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$PROJECT_DIR/reports/zap" \
                          python:3.12-alpine \
                          python zap_to_html.py

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$PROJECT_DIR" \
                          python:3.12-alpine \
                          python reports/zap/print_zap_summary.py reports/zap/zap-report.json

                        echo "Contenu reports/zap :"
                        ls -lah "$PROJECT_DIR/reports/zap/"
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eu

                    echo "=== OPA SECURITY GATE ==="
                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$PROJECT_DIR" \
                      python:3.12-alpine \
                      python reports/opa/build_input.py

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$PROJECT_DIR" \
                      openpolicyagent/opa:latest \
                      eval \
                      --format raw \
                      --data "$PROJECT_DIR/policy/security-gate.rego" \
                      --input "$PROJECT_DIR/reports/opa/input.json" \
                      "data.security.allow" | tee "$PROJECT_DIR/reports/opa/opa-result.txt"

                    if ! grep -qx "true" "$PROJECT_DIR/reports/opa/opa-result.txt"; then
                        echo ""
                        echo "============================================================"
                        echo "  OPA SECURITY GATE : ECHEC"
                        echo "  Le pipeline est bloque. Consultez le resume ci-dessus."
                        echo "  Criteres de blocage :"
                        echo "    - Trivy CRITICAL/HIGH non attendus > 0"
                        echo "    - Gitleaks secrets non attendus > 0"
                        echo "    - ZAP HIGH non attendus > 0"
                        echo "============================================================"
                        exit 1
                    fi

                    echo "OPA Security Gate : PASS"
                '''
            }
        }
    }

    post {
        always {
            sh '''
                set +e
                docker run --rm \
                  -u 0:0 \
                  -v "$WORKSPACE:/ws" \
                  alpine:3.19 \
                  sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null || true"
            '''

            script {
                env.SECURITY_BUILD_RESULT = currentBuild.currentResult ?: 'UNKNOWN'
            }

            sh '''
                set +e
                if [ -d "$PROJECT_DIR" ] && [ -f "$PROJECT_DIR/ci/security-dashboard/build_security_dashboard.py" ]; then
                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$PROJECT_DIR" \
                      -e SECURITY_BUILD_RESULT="$SECURITY_BUILD_RESULT" \
                      -e JOB_NAME="$JOB_NAME" \
                      -e BUILD_NUMBER="$BUILD_NUMBER" \
                      -e BUILD_URL="$BUILD_URL" \
                      python:3.12-alpine \
                      python ci/security-dashboard/build_security_dashboard.py
                else
                    echo "Security dashboard script absent - generation ignoree."
                fi
            '''

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
                } else {
                    echo 'Trivy report absent - publication recordIssues ignoree.'
                }
            }

            script {
                if (fileExists('src/reports/zap/zap-report.html')) {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'src/reports/zap',
                        reportFiles          : 'zap-report.html',
                        reportName           : 'ZAP Web Report'
                    ])
                } else {
                    echo 'ZAP HTML report absent - publication HTML ignoree.'
                }
            }

            script {
                if (fileExists('src/reports/security-dashboard/security-dashboard.html')) {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'src/reports',
                        reportFiles          : 'security-dashboard/security-dashboard.html',
                        reportName           : 'Security Dashboard'
                    ])
                } else {
                    echo 'Security dashboard absent - publication HTML ignoree.'
                }
            }

            script {
                if (fileExists('src/reports')) {
                    archiveArtifacts artifacts: 'src/reports/**/*', allowEmptyArchive: true, fingerprint: true
                } else {
                    echo 'Dossier reports absent - archivage ignore.'
                }
            }

            sh '''
                set +e
                docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        failure {
            echo 'Pipeline FAILED - consulter les logs de scan et les rapports archives.'
        }

        unstable {
            echo 'Pipeline UNSTABLE - des problemes de securite ont ete detectes; voir les resumes console Gitleaks, Trivy, SonarQube et ZAP.'
        }

        success {
            echo 'Pipeline SUCCESS - tous les security gates sont passes.'
        }
    }
}
