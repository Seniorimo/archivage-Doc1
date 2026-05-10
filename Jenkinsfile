pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
    }

    environment {
        APP_NAME         = 'archivage-Doc'
        APP_CONTAINER    = 'app-archivage'
        MYSQL_CONTAINER  = 'mysql-archivage'
        NETWORK_NAME     = 'archivage-net'
        APP_PORT         = '8090'
        PROJECT_SUBDIR   = 'src'

        JENKINS_HOME_DIR = '/var/jenkins_home'
        MAVEN_CACHE_DIR  = '/var/jenkins_home/.m2'
        MAVEN_REPO       = '/var/jenkins_home/.m2/repository'
        TRIVY_CACHE      = '/var/jenkins_home/.trivycache'

        SONARQUBE_ENV    = 'sonar'

        // Images pinning for stability
        PYTHON_IMAGE     = 'python:3.12.8-alpine3.20'
        MAVEN_IMAGE      = 'maven:3.9.9-eclipse-temurin-17'
        GITLEAKS_IMAGE   = 'zricethezav/gitleaks:v8.18.4'
        TRIVY_IMAGE      = 'ghcr.io/aquasecurity/trivy:0.70.0'
        ZAP_IMAGE        = 'owasp/zap2docker-stable'
        OPA_IMAGE        = 'openpolicyagent/opa:0.70.0'
        MYSQL_IMAGE      = 'mysql:8.0.40'
        CURL_IMAGE       = 'curlimages/curl:8.10.1'
    }

    stages {

        stage('Init') {
            steps {
                script {
                    env.PROJECT_DIR      = "${env.WORKSPACE}/${env.PROJECT_SUBDIR}"
                    env.REPORTS_DIR      = "${env.PROJECT_DIR}/reports"
                    env.POLICY_DIR       = "${env.PROJECT_DIR}/policy"
                    env.UPLOADS_DIR      = "${env.PROJECT_DIR}/uploads"
                    env.JENKINS_UID      = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID      = sh(returnStdout: true, script: 'id -g').trim()
                    env.DOCKER_GROUP_GID = sh(returnStdout: true, script: 'stat -c %g /var/run/docker.sock 2>/dev/null || true').trim()
                }

                sh '''
                    set -eux
                    echo "=== INIT ==="
                    echo "WORKSPACE       = $WORKSPACE"
                    echo "PROJECT_DIR     = $PROJECT_DIR"
                    echo "REPORTS_DIR     = $REPORTS_DIR"
                    echo "POLICY_DIR      = $POLICY_DIR"
                    echo "UPLOADS_DIR     = $UPLOADS_DIR"
                    echo "JENKINS_UID:GID = $JENKINS_UID:$JENKINS_GID"
                    echo "DOCKER_SOCK_GID = ${DOCKER_GROUP_GID:-<empty>}"

                    test -S /var/run/docker.sock || {
                        echo "[ERREUR] /var/run/docker.sock introuvable"
                        exit 1
                    }

                    mkdir -p \
                        "$WORKSPACE" \
                        "$PROJECT_DIR" \
                        "$REPORTS_DIR" \
                        "$POLICY_DIR" \
                        "$UPLOADS_DIR" \
                        "$MAVEN_CACHE_DIR/repository" \
                        "$TRIVY_CACHE"

                    chown -R "$JENKINS_UID:$JENKINS_GID" \
                        "$WORKSPACE" \
                        "$MAVEN_CACHE_DIR" \
                        "$TRIVY_CACHE" || true

                    chmod 755 "$WORKSPACE" "$PROJECT_DIR" "$REPORTS_DIR" "$POLICY_DIR" "$UPLOADS_DIR" || true
                    chmod 700 "$MAVEN_CACHE_DIR" "$TRIVY_CACHE" || true
                '''
            }
        }

        stage('Force Clean Workspace') {
            steps {
                sh '''
                    set -eux
                    echo "=== FORCE CLEAN WORKSPACE ==="

                    docker run --rm \
                        -u 0:0 \
                        -v "$WORKSPACE:/ws" \
                        alpine:3.19 \
                        sh -euxc '
                            find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
                            mkdir -p /ws/src
                            chown -R '"${JENKINS_UID}"':'"${JENKINS_GID}"' /ws
                            ls -la /ws
                        '

                    echo "Workspace nettoyé."
                '''
            }
        }

        stage('Checkout') {
            steps {
                dir("${PROJECT_SUBDIR}") {
                    deleteDir()
                    checkout scm
                }

                script {
                    env.GIT_SHA = sh(
                        returnStdout: true,
                        script: '''
                            set -eu
                            cd "$PROJECT_DIR"
                            git rev-parse HEAD
                        '''
                    ).trim()
                    env.GIT_SHORT_SHA = env.GIT_SHA.take(7)
                }

                sh '''
                    set -eux
                    echo "=== CHECKOUT ==="
                    echo "GIT_SHA       = $GIT_SHA"
                    echo "GIT_SHORT_SHA = $GIT_SHORT_SHA"
                    test -f "$PROJECT_DIR/pom.xml" || {
                        echo "[ERREUR] pom.xml introuvable dans $PROJECT_DIR"
                        exit 1
                    }
                    chown -R "$JENKINS_UID:$JENKINS_GID" "$PROJECT_DIR" || true
                '''
            }
        }

        stage('Login & Pull Image') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'docker-hub-creds',
                    usernameVariable: 'DOCKER_HUB_USERNAME',
                    passwordVariable: 'DOCKER_HUB_PASSWORD'
                )]) {
                    script {
                        env.RESOLVED_IMAGE_TAG = sh(
                            returnStdout: true,
                            script: '''
                                set -eu
                                docker run --rm -i \
                                  -u "$JENKINS_UID:$JENKINS_GID" \
                                  -e HOME=/tmp \
                                  -e DOCKER_HUB_USERNAME="$DOCKER_HUB_USERNAME" \
                                  -e DOCKER_HUB_PASSWORD="$DOCKER_HUB_PASSWORD" \
                                  -e GIT_SHA="$GIT_SHA" \
                                  "$PYTHON_IMAGE" \
                                  python - <<'PY'
import json
import os
import sys
import urllib.request

username = os.environ["DOCKER_HUB_USERNAME"].strip()
pat = os.environ["DOCKER_HUB_PASSWORD"].strip()
git_sha = os.environ["GIT_SHA"].strip()
short_sha = git_sha[:7]
repo = "archivage-app"

def req(url, method="GET", data=None, headers=None):
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {},
        method=method
    )
    with urllib.request.urlopen(request, timeout=30) as resp:
        return resp.read().decode("utf-8")

try:
    token_payload = json.dumps({
        "identifier": username,
        "secret": pat
    }).encode("utf-8")

    token_resp = req(
        "https://hub.docker.com/v2/auth/token",
        method="POST",
        data=token_payload,
        headers={"Content-Type": "application/json"}
    )
    token = json.loads(token_resp).get("access_token", "")
except Exception as e:
    print(f"ERREUR_AUTH: {e}", file=sys.stderr)
    sys.exit(1)

if not token:
    print("ERREUR_AUTH: token vide", file=sys.stderr)
    sys.exit(1)

url = f"https://hub.docker.com/v2/namespaces/{username}/repositories/{repo}/tags?page_size=100&ordering=-last_updated"
tags = []

while url:
    try:
        resp = req(url, headers={"Authorization": f"Bearer {token}"})
        data = json.loads(resp)
    except Exception as e:
        print(f"ERREUR_TAGS: {e}", file=sys.stderr)
        sys.exit(1)

    tags.extend([
        item.get("name", "").strip()
        for item in data.get("results", []) or []
        if item.get("name")
    ])
    url = data.get("next")

for candidate in [git_sha, short_sha]:
    if candidate and candidate in tags:
        print(candidate)
        sys.exit(0)

print(
    f"ERREUR: tag Docker Hub exact introuvable pour le commit {git_sha} "
    f"(attendus: {git_sha} ou {short_sha})",
    file=sys.stderr
)
sys.exit(1)
PY
                            '''
                        ).trim()

                        if (!env.RESOLVED_IMAGE_TAG?.trim()) {
                            error("RESOLVED_IMAGE_TAG est vide")
                        }

                        env.DOCKER_IMAGE = "${env.DOCKER_HUB_USERNAME}/archivage-app:${env.RESOLVED_IMAGE_TAG}"
                        echo "IMAGE_TAG exact : ${env.RESOLVED_IMAGE_TAG}"
                        echo "Image cible     : ${env.DOCKER_IMAGE}"
                    }

                    sh '''
                        set -eux
                        echo "=== LOGIN & PULL IMAGE ==="
                        test -n "$RESOLVED_IMAGE_TAG" || {
                            echo "[ERREUR] RESOLVED_IMAGE_TAG vide"
                            exit 1
                        }
                        test -n "$DOCKER_IMAGE" || {
                            echo "[ERREUR] DOCKER_IMAGE vide"
                            exit 1
                        }

                        trap 'docker logout >/dev/null 2>&1 || true' EXIT
                        echo "$DOCKER_HUB_PASSWORD" | docker login -u "$DOCKER_HUB_USERNAME" --password-stdin
                        docker pull "$DOCKER_IMAGE"
                        docker image inspect "$DOCKER_IMAGE" >/dev/null
                    '''
                }
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eux
                    echo "=== PREPARE WORKSPACE ==="

                    mkdir -p \
                        "$REPORTS_DIR/gitleaks" \
                        "$REPORTS_DIR/trivy" \
                        "$REPORTS_DIR/sbom" \
                        "$REPORTS_DIR/zap" \
                        "$REPORTS_DIR/opa" \
                        "$REPORTS_DIR/dashboard" \
                        "$POLICY_DIR" \
                        "$UPLOADS_DIR"

                    chown -R "$JENKINS_UID:$JENKINS_GID" "$PROJECT_DIR" || true
                    find "$PROJECT_DIR" -type d -exec chmod 755 {} + || true
                    find "$PROJECT_DIR" -type f -exec chmod 644 {} + || true

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"

                    if [ -f "$PROJECT_DIR/generate_dashboard.py" ]; then
                        chmod 755 "$PROJECT_DIR/generate_dashboard.py" || true
                        echo "Dashboard script détecté."
                    else
                        echo "[WARN] generate_dashboard.py absent"
                    fi

                    cat > "$POLICY_DIR/security-gate.rego" <<'REGO'
package security

default allow := false

technical_ok if {
    input.scan_status.gitleaks == "ok"
    input.scan_status.trivy == "ok"
    input.scan_status.zap == "ok"
}

policy_ok if {
    input.trivy.critical == 0
    count(input.gitleaks) == 0
    input.zap.high == 0
}

allow if {
    technical_ok
    policy_ok
}
REGO

                    cat > "$REPORTS_DIR/opa/build_input.py" <<'PYEOF'
import json
from pathlib import Path

def load_json(path_str):
    p = Path(path_str)
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

scan_status = {
    "gitleaks": "missing",
    "trivy": "missing",
    "zap": "missing"
}

gitleaks_raw = load_json("reports/gitleaks/gitleaks-report.json")
if isinstance(gitleaks_raw, list):
    gitleaks = gitleaks_raw
    scan_status["gitleaks"] = "ok"
else:
    gitleaks = []

trivy_raw = load_json("reports/trivy/trivy-report.json")
if isinstance(trivy_raw, dict) and isinstance(trivy_raw.get("Results", []), list):
    trivy = trivy_raw
    scan_status["trivy"] = "ok"
else:
    trivy = {"Results": []}

zap_raw = load_json("reports/zap/zap-report.json")
if isinstance(zap_raw, dict) and isinstance(zap_raw.get("site", []), list):
    zap = zap_raw
    scan_status["zap"] = "ok"
else:
    zap = {"site": [{"alerts": []}]}

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in trivy.get("Results", []) or []:
    for vuln in result.get("Vulnerabilities", []) or []:
        s = (vuln.get("Severity") or "").upper()
        if s in sev:
            sev[s] += 1

zap_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        rc = str(alert.get("riskcode", "0"))
        if rc == "3":
            zap_counts["high"] += 1
        elif rc == "2":
            zap_counts["medium"] += 1
        elif rc == "1":
            zap_counts["low"] += 1
        else:
            zap_counts["info"] += 1

payload = {
    "scan_status": scan_status,
    "gitleaks": gitleaks,
    "trivy": {
        "critical": sev["CRITICAL"],
        "high": sev["HIGH"],
        "medium": sev["MEDIUM"],
        "low": sev["LOW"]
    },
    "zap": zap_counts
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(
    json.dumps(payload, indent=2),
    encoding="utf-8"
)
PYEOF

                    cat > "$REPORTS_DIR/zap/parse_zap_log.py" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

if len(sys.argv) != 3:
    print("Usage: parse_zap_log.py <log> <json>", file=sys.stderr)
    sys.exit(1)

src = Path(sys.argv[1])
out = Path(sys.argv[2])

if not src.exists() or src.stat().st_size == 0:
    print("ZAP log absent ou vide", file=sys.stderr)
    sys.exit(1)

lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()

alert_re = re.compile(r'^(WARN|FAIL)-(?:NEW|INPROG):\s+(.+?)\s+\[(\d+)\]\s+x\s+(\d+)\s*$')
url_re = re.compile(r'^\s*(https?://\S+)\s+\(([^)]+)\)\s*$')

alerts = []
current = None

for raw in lines:
    line = raw.rstrip()

    m = alert_re.match(line.strip())
    if m:
        level, name, plugin_id, count = m.groups()
        riskcode = "3" if level == "FAIL" else "2"
        current = {
            "alert": name,
            "name": name,
            "pluginid": plugin_id,
            "riskcode": riskcode,
            "desc": "Alert parsed from zap-baseline.py console output.",
            "solution": "Review the affected response, headers, cookies, and client-side resources.",
            "instances": [],
            "count": int(count)
        }
        alerts.append(current)
        continue

    m = url_re.match(line)
    if m and current is not None:
        uri, evidence = m.groups()
        current["instances"].append({
            "uri": uri,
            "evidence": evidence,
            "method": "GET"
        })

data = {
    "site": [
        {
            "@name": "baseline-scan",
            "alerts": alerts
        }
    ]
}

out.write_text(json.dumps(data, indent=2), encoding="utf-8")
print(f"Parsed {len(alerts)} ZAP alerts into {out}")
PYEOF

                    cat > "$REPORTS_DIR/zap/zap_to_html.py" <<'PYEOF'
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
target = "N/A"

for site in data.get("site", []) or []:
    if target == "N/A":
        target = site.get("@name", site.get("name", "N/A"))
    for alert in site.get("alerts", []) or []:
        all_alerts.append(alert)

all_alerts.sort(key=lambda a: -int(a.get("riskcode", 0)))

rows = ""
for a in all_alerts:
    rc = str(a.get("riskcode", "0"))
    name = a.get("alert", a.get("name", "?"))
    desc = (a.get("desc", "") or "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    sol = (a.get("solution", "") or "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    url = ""
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
    table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,.1); }}
    th {{ background: #2c3e50; color: #fff; padding: 10px; text-align: left; }}
    td {{ padding: 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
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
      {rows if rows else '<tr><td colspan="4" style="text-align:center;padding:30px;color:#27ae60"><strong>Aucune alerte détectée</strong></td></tr>'}
    </tbody>
  </table>
</body>
</html>"""

out.write_text(html, encoding="utf-8")
print("Rapport HTML ZAP généré : " + str(out))
PYEOF

                    cat > "$REPORTS_DIR/dashboard/patch_csp.py" <<'PYEOF'
from pathlib import Path
import sys

META = """<meta http-equiv="Content-Security-Policy" content="default-src 'self' data: blob: https:; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:;">"""

def patch(path_str: str):
    p = Path(path_str)
    if not p.exists():
        print(f"[SKIP] Fichier absent : {p}")
        return
    html = p.read_text(encoding="utf-8", errors="ignore")
    if 'http-equiv="Content-Security-Policy"' in html or "http-equiv='Content-Security-Policy'" in html:
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

                    chown -R "$JENKINS_UID:$JENKINS_GID" "$PROJECT_DIR" || true
                '''
            }
        }

        stage('Compile Light') {
            steps {
                sh '''
                    set -eux
                    echo "=== COMPILE LIGHT ==="

                    mkdir -p "$MAVEN_CACHE_DIR/repository"
                    chown -R "$JENKINS_UID:$JENKINS_GID" "$MAVEN_CACHE_DIR" || true

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp/jenkins-home \
                        -e MAVEN_CONFIG=/var/jenkins_home/.m2 \
                        -v "$PROJECT_DIR:$PROJECT_DIR" \
                        -v "$MAVEN_CACHE_DIR:$MAVEN_CACHE_DIR" \
                        -w "$PROJECT_DIR" \
                        "$MAVEN_IMAGE" \
                        sh -lc '
                            mkdir -p "$HOME" "$MAVEN_CONFIG"
                            mvn -B -f "'"$PROJECT_DIR"'/pom.xml" \
                                -Dmaven.repo.local="'"$MAVEN_REPO"'" \
                                clean compile -DskipTests
                        '
                '''
            }
        }

        stage('Security Scans') {
            parallel {

                stage('Secrets - Gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eux
                                echo "=== GITLEAKS ==="

                                rm -f "$REPORTS_DIR/gitleaks/gitleaks-report.json"

                                docker run --rm \
                                    --user "$JENKINS_UID:$JENKINS_GID" \
                                    -e HOME=/tmp/jenkins-home \
                                    -v "$PROJECT_DIR:$PROJECT_DIR" \
                                    -w "$PROJECT_DIR" \
                                    "$GITLEAKS_IMAGE" detect \
                                        --source . \
                                        --log-opts="--all" \
                                        --report-format json \
                                        --report-path "$REPORTS_DIR/gitleaks/gitleaks-report.json" \
                                        --exit-code 0

                                test -s "$REPORTS_DIR/gitleaks/gitleaks-report.json" || {
                                    echo "[ERREUR] gitleaks-report.json absent ou vide"
                                    exit 1
                                }

                                chown "$JENKINS_UID:$JENKINS_GID" "$REPORTS_DIR/gitleaks/gitleaks-report.json" || true
                                ls -lh "$REPORTS_DIR/gitleaks/gitleaks-report.json"
                            '''
                        }
                    }
                }

                stage('SCA - Trivy Image') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eux
                                echo "=== TRIVY ==="

                                test -S /var/run/docker.sock || {
                                    echo "[ERREUR] /var/run/docker.sock absent"
                                    exit 1
                                }

                                docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1 || {
                                    echo "[ERREUR] Image absente localement : $DOCKER_IMAGE"
                                    exit 1
                                }

                                mkdir -p "$REPORTS_DIR/trivy" "$TRIVY_CACHE"
                                rm -f "$REPORTS_DIR/trivy/trivy-report.json" "$REPORTS_DIR/trivy/trivy.stderr.log"
                                chmod 700 "$TRIVY_CACHE" || true

                                EXTRA_GROUP_ARGS=""
                                if [ -n "${DOCKER_GROUP_GID:-}" ]; then
                                    EXTRA_GROUP_ARGS="--group-add ${DOCKER_GROUP_GID}"
                                fi

                                docker run --rm \
                                    --user "$JENKINS_UID:$JENKINS_GID" \
                                    $EXTRA_GROUP_ARGS \
                                    -e HOME=/tmp/jenkins-home \
                                    -e TRIVY_CACHE_DIR="$TRIVY_CACHE" \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$TRIVY_CACHE:$TRIVY_CACHE" \
                                    -v "$REPORTS_DIR/trivy:$REPORTS_DIR/trivy" \
                                    -v "$PROJECT_DIR:$PROJECT_DIR" \
                                    -w "$PROJECT_DIR" \
                                    "$TRIVY_IMAGE" image \
                                        --cache-dir "$TRIVY_CACHE" \
                                        --no-progress \
                                        --scanners vuln \
                                        --severity CRITICAL,HIGH,MEDIUM,LOW \
                                        --format json \
                                        --output "$REPORTS_DIR/trivy/trivy-report.json" \
                                        "$DOCKER_IMAGE" \
                                    2> "$REPORTS_DIR/trivy/trivy.stderr.log"

                                test -s "$REPORTS_DIR/trivy/trivy-report.json" || {
                                    echo "[ERREUR] trivy-report.json absent ou vide"
                                    tail -n 100 "$REPORTS_DIR/trivy/trivy.stderr.log" || true
                                    exit 1
                                }

                                chown -R "$JENKINS_UID:$JENKINS_GID" "$REPORTS_DIR/trivy" "$TRIVY_CACHE" || true
                                ls -lh "$REPORTS_DIR/trivy/trivy-report.json" "$REPORTS_DIR/trivy/trivy.stderr.log"
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube Analysis') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            script {
                                withSonarQubeEnv("${SONARQUBE_ENV}") {
                                    sh '''
                                        set -eux
                                        echo "=== SONARQUBE ==="

                                        test -d "$PROJECT_DIR/target/classes" || {
                                            echo "[ERREUR] target/classes introuvable"
                                            exit 1
                                        }

                                        docker run --rm \
                                            --user "$JENKINS_UID:$JENKINS_GID" \
                                            -e HOME=/tmp/jenkins-home \
                                            -e MAVEN_CONFIG=/var/jenkins_home/.m2 \
                                            --network "$NETWORK_NAME" \
                                            --add-host=host.docker.internal:host-gateway \
                                            -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                            -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                            -v "$PROJECT_DIR:$PROJECT_DIR" \
                                            -v "$MAVEN_CACHE_DIR:$MAVEN_CACHE_DIR" \
                                            -w "$PROJECT_DIR" \
                                            "$MAVEN_IMAGE" \
                                            sh -lc '
                                                mkdir -p "$HOME" "$MAVEN_CONFIG"
                                                mvn -B -f "'"$PROJECT_DIR"'/pom.xml" \
                                                    -Dmaven.repo.local="'"$MAVEN_REPO"'" \
                                                    org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                                    -Dsonar.projectKey="'"$APP_NAME"'" \
                                                    -Dsonar.host.url="'"$SONAR_HOST_URL"'" \
                                                    -Dsonar.token="'"$SONAR_AUTH_TOKEN"'" \
                                                    -Dsonar.java.binaries=target/classes \
                                                    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
                                            '
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
                                set -eux
                                echo "=== CYCLONEDX SBOM ==="

                                rm -f "$REPORTS_DIR/sbom/bom.xml" "$REPORTS_DIR/sbom/bom.json"

                                docker run --rm \
                                    --user "$JENKINS_UID:$JENKINS_GID" \
                                    -e HOME=/tmp/jenkins-home \
                                    -e MAVEN_CONFIG=/var/jenkins_home/.m2 \
                                    -v "$PROJECT_DIR:$PROJECT_DIR" \
                                    -v "$MAVEN_CACHE_DIR:$MAVEN_CACHE_DIR" \
                                    -w "$PROJECT_DIR" \
                                    "$MAVEN_IMAGE" \
                                    sh -lc '
                                        mkdir -p "$HOME" "$MAVEN_CONFIG"
                                        mvn -B -f "'"$PROJECT_DIR"'/pom.xml" \
                                            -Dmaven.repo.local="'"$MAVEN_REPO"'" \
                                            org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                                            -DoutputFormat=all
                                    '

                                test -f "$PROJECT_DIR/target/bom.xml" && cp -f "$PROJECT_DIR/target/bom.xml" "$REPORTS_DIR/sbom/bom.xml" || true
                                test -f "$PROJECT_DIR/target/bom.json" && cp -f "$PROJECT_DIR/target/bom.json" "$REPORTS_DIR/sbom/bom.json" || true

                                chown -R "$JENKINS_UID:$JENKINS_GID" "$REPORTS_DIR/sbom" || true
                                ls -lah "$REPORTS_DIR/sbom" || true
                            '''
                        }
                    }
                }
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eux
                    echo "=== DEPLOY MYSQL ==="

                    docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true

                    docker run -d \
                        --name "$MYSQL_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        -e MYSQL_ROOT_PASSWORD=root \
                        -e MYSQL_DATABASE=archivage_doc \
                        -e MYSQL_USER=archivage_user \
                        -e MYSQL_PASSWORD=archivage_pass \
                        "$MYSQL_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        if docker run --rm --network "$NETWORK_NAME" "$MYSQL_IMAGE" \
                                mysqladmin ping -h"$MYSQL_CONTAINER" -uroot -proot --silent; then
                            READY=1
                            break
                        fi
                        sleep 5
                    done

                    test "$READY" -eq 1 || {
                        echo "[ERREUR] MySQL ne répond pas après 30 tentatives"
                        docker logs "$MYSQL_CONTAINER" --tail 200 || true
                        exit 1
                    }
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    set -eux
                    echo "=== DEPLOY APP ==="

                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                    mkdir -p "$UPLOADS_DIR"
                    chown -R "$JENKINS_UID:$JENKINS_GID" "$UPLOADS_DIR" || true

                    _GITHUB_SECRET="${GITHUB_OAUTH_SECRET:-changeme-github}"
                    _JWT_SECRET="${JWT_SECRET:-changeme-jwt-secret-32chars-min}"

                    docker run -d \
                        --name "$APP_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        --restart on-failure:5 \
                        -v "$UPLOADS_DIR:/app/uploads" \
                        -e SPRING_PROFILES_ACTIVE=docker \
                        -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" \
                        -e SPRING_DATASOURCE_USERNAME="archivage_user" \
                        -e SPRING_DATASOURCE_PASSWORD="archivage_pass" \
                        -e GITHUB_OAUTH_SECRET="$_GITHUB_SECRET" \
                        -e JWT_SECRET="$_JWT_SECRET" \
                        "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" "$CURL_IMAGE" \
                            -s -o /dev/null -w "%{http_code}" \
                            "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)

                        echo "HTTP=$CODE"

                        if echo "$CODE" | grep -qE '^(200|301|302|401|403|404)$'; then
                            READY=1
                            break
                        fi
                        sleep 5
                    done

                    test "$READY" -eq 1 || {
                        echo "[ERREUR] Application non joignable sur /actuator/health"
                        docker logs "$APP_CONTAINER" --tail 200 || true
                        exit 1
                    }
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eux
                        echo "=== ZAP BASELINE ==="

                        mkdir -p "$REPORTS_DIR/zap"
                        rm -f \
                            "$REPORTS_DIR/zap/zap-report.json" \
                            "$REPORTS_DIR/zap/zap-report.html" \
                            "$REPORTS_DIR/zap/zap-baseline.log" \
                            "$REPORTS_DIR/zap/zap-exit-code.txt"

                        docker run --rm \
                            --user "$JENKINS_UID:$JENKINS_GID" \
                            --network "$NETWORK_NAME" \
                            -e HOME=/tmp/jenkins-home \
                            -v "$REPORTS_DIR/zap:/zap/wrk" \
                            "$ZAP_IMAGE" \
                            bash -lc '
                                cd /zap
                                status=0
                                ./zap-baseline.py \
                                    -t "http://'"$APP_CONTAINER"':'"$APP_PORT"'/" \
                                    -r /zap/wrk/zap-report.html \
                                    -a -j -I -m 5 2>&1 | tee /zap/wrk/zap-baseline.log || status=$?
                                echo "$status" > /zap/wrk/zap-exit-code.txt
                                exit 0
                            '

                        test -s "$REPORTS_DIR/zap/zap-baseline.log" || {
                            echo "[ERREUR] zap-baseline.log absent ou vide"
                            exit 1
                        }

                        docker run --rm \
                            --user "$JENKINS_UID:$JENKINS_GID" \
                            -e HOME=/tmp/jenkins-home \
                            -v "$REPORTS_DIR/zap:$REPORTS_DIR/zap" \
                            -w "$REPORTS_DIR/zap" \
                            "$PYTHON_IMAGE" \
                            python parse_zap_log.py zap-baseline.log zap-report.json

                        test -s "$REPORTS_DIR/zap/zap-report.json" || {
                            echo "[ERREUR] zap-report.json absent ou vide"
                            exit 1
                        }

                        # On garde le HTML brut de ZAP s'il existe, sinon on en produit un simple à partir du JSON.
                        if [ ! -s "$REPORTS_DIR/zap/zap-report.html" ]; then
                            docker run --rm \
                                --user "$JENKINS_UID:$JENKINS_GID" \
                                -e HOME=/tmp/jenkins-home \
                                -v "$REPORTS_DIR/zap:$REPORTS_DIR/zap" \
                                -w "$REPORTS_DIR/zap" \
                                "$PYTHON_IMAGE" \
                                python zap_to_html.py
                        fi

                        test -s "$REPORTS_DIR/zap/zap-report.html" || {
                            echo "[ERREUR] zap-report.html absent ou vide"
                            exit 1
                        }

                        chown -R "$JENKINS_UID:$JENKINS_GID" "$REPORTS_DIR/zap" || true
                        ls -lah "$REPORTS_DIR/zap"
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eux
                    echo "=== OPA INPUT BUILD ==="

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp/jenkins-home \
                        -v "$PROJECT_DIR:$PROJECT_DIR" \
                        -w "$PROJECT_DIR" \
                        "$PYTHON_IMAGE" \
                        python reports/opa/build_input.py

                    test -s "$REPORTS_DIR/opa/input.json" || {
                        echo "[ERREUR TECHNIQUE] input.json OPA absent ou vide"
                        exit 1
                    }

                    echo "=== OPA INPUT ==="
                    cat "$REPORTS_DIR/opa/input.json"
                '''

                script {
                    def technicalOk = sh(
                        returnStatus: true,
                        script: '''
                            set -eu
                            docker run --rm \
                                --user "$JENKINS_UID:$JENKINS_GID" \
                                -e HOME=/tmp/jenkins-home \
                                -v "$PROJECT_DIR:$PROJECT_DIR" \
                                -w "$PROJECT_DIR" \
                                "$OPA_IMAGE" \
                                eval \
                                    --format raw \
                                    --data "$POLICY_DIR/security-gate.rego" \
                                    --input "$REPORTS_DIR/opa/input.json" \
                                    "data.security.technical_ok" \
                                > "$REPORTS_DIR/opa/opa-technical-ok.txt"

                            grep -qx "true" "$REPORTS_DIR/opa/opa-technical-ok.txt"
                        '''
                    ) == 0

                    if (!technicalOk) {
                        sh '''
                            set -eu
                            docker run --rm \
                                --user "$JENKINS_UID:$JENKINS_GID" \
                                -e HOME=/tmp/jenkins-home \
                                -v "$PROJECT_DIR:$PROJECT_DIR" \
                                -w "$PROJECT_DIR" \
                                "$OPA_IMAGE" \
                                eval \
                                    --format pretty \
                                    --data "$POLICY_DIR/security-gate.rego" \
                                    --input "$REPORTS_DIR/opa/input.json" \
                                    "data.security" \
                                | tee "$REPORTS_DIR/opa/opa-debug.txt"
                        '''
                        error("[ERREUR TECHNIQUE] Un rapport requis est absent ou invalide. Voir reports/opa/input.json et reports/opa/opa-debug.txt")
                    }

                    def policyOk = sh(
                        returnStatus: true,
                        script: '''
                            set -eu
                            docker run --rm \
                                --user "$JENKINS_UID:$JENKINS_GID" \
                                -e HOME=/tmp/jenkins-home \
                                -v "$PROJECT_DIR:$PROJECT_DIR" \
                                -w "$PROJECT_DIR" \
                                "$OPA_IMAGE" \
                                eval \
                                    --format pretty \
                                    --data "$POLICY_DIR/security-gate.rego" \
                                    --input "$REPORTS_DIR/opa/input.json" \
                                    "data.security" \
                                | tee "$REPORTS_DIR/opa/opa-debug.txt"

                            docker run --rm \
                                --user "$JENKINS_UID:$JENKINS_GID" \
                                -e HOME=/tmp/jenkins-home \
                                -v "$PROJECT_DIR:$PROJECT_DIR" \
                                -w "$PROJECT_DIR" \
                                "$OPA_IMAGE" \
                                eval \
                                    --format raw \
                                    --data "$POLICY_DIR/security-gate.rego" \
                                    --input "$REPORTS_DIR/opa/input.json" \
                                    "data.security.allow" \
                                > "$REPORTS_DIR/opa/opa-result.txt"

                            grep -qx "true" "$REPORTS_DIR/opa/opa-result.txt"
                        '''
                    ) == 0

                    if (!policyOk) {
                        currentBuild.result = 'FAILURE'
                        error("[ECHEC POLICY OPA] Les scans existent, mais la policy sécurité n’est pas satisfaite. Voir reports/opa/input.json et reports/opa/opa-debug.txt")
                    }
                }
            }
        }
    }

    post {
        always {
            sh '''
                set +e
                echo "=== POST DIAGNOSTICS ==="
                ls -lah "$PROJECT_DIR" || true
                find "$REPORTS_DIR" -maxdepth 2 -type f -ls 2>/dev/null || true
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
                }
            }

            script {
                if (fileExists('src/generate_dashboard.py')) {
                    withSonarQubeEnv("${SONARQUBE_ENV}") {
                        sh '''
                            set +e
                            echo "=== POST DASHBOARD ==="

                            mkdir -p "$REPORTS_DIR/dashboard"
                            docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME" >/dev/null 2>&1 || true

                            docker run --rm \
                                --user "$JENKINS_UID:$JENKINS_GID" \
                                -e HOME=/tmp/jenkins-home \
                                --network "$NETWORK_NAME" \
                                --add-host=host.docker.internal:host-gateway \
                                -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                -v "$PROJECT_DIR:$PROJECT_DIR" \
                                -w "$PROJECT_DIR" \
                                "$PYTHON_IMAGE" \
                                python generate_dashboard.py \
                                    --reports reports \
                                    --output reports/dashboard/security-dashboard.html \
                                    --project "$APP_NAME" \
                                    --sonar-url "$SONAR_HOST_URL" \
                                    --sonar-token "$SONAR_AUTH_TOKEN" \
                                    --sonar-project "$APP_NAME" || true

                            chown -R "$JENKINS_UID:$JENKINS_GID" "$REPORTS_DIR/dashboard" || true
                        '''
                    }
                }
            }

            script {
                if (fileExists('src/reports/dashboard/patch_csp.py')) {
                    sh '''
                        set +e
                        echo "=== POST CSP PATCH ==="

                        docker run --rm \
                            --user "$JENKINS_UID:$JENKINS_GID" \
                            -e HOME=/tmp/jenkins-home \
                            -v "$PROJECT_DIR:$PROJECT_DIR" \
                            -w "$PROJECT_DIR" \
                            "$PYTHON_IMAGE" \
                            python reports/dashboard/patch_csp.py \
                                reports/dashboard/security-dashboard.html \
                                reports/zap/zap-report.html || true
                    '''
                } else {
                    echo 'patch_csp.py absent, patch CSP ignoré.'
                }
            }

            script {
                if (fileExists('src/reports/dashboard/security-dashboard.html')) {
                    publishHTML(target: [
                        allowMissing          : true,
                        alwaysLinkToLastBuild : true,
                        keepAll               : true,
                        reportDir             : 'src/reports/dashboard',
                        reportFiles           : 'security-dashboard.html',
                        reportName            : 'Security Dashboard',
                        escapeUnderscores     : false
                    ])
                }
            }

            script {
                if (fileExists('src/reports/zap/zap-report.html')) {
                    publishHTML(target: [
                        allowMissing          : true,
                        alwaysLinkToLastBuild : true,
                        keepAll               : false,
                        reportDir             : 'src/reports/zap',
                        reportFiles           : 'zap-report.html',
                        reportName            : 'ZAP Web Report',
                        escapeUnderscores     : false
                    ])
                }
            }

            script {
                if (fileExists('src/reports')) {
                    archiveArtifacts(
                        artifacts: [
                            'src/reports/gitleaks/gitleaks-report.json',
                            'src/reports/trivy/trivy-report.json',
                            'src/reports/trivy/trivy.stderr.log',
                            'src/reports/zap/zap-baseline.log',
                            'src/reports/zap/zap-exit-code.txt',
                            'src/reports/zap/zap-report.html',
                            'src/reports/zap/zap-report.json',
                            'src/reports/opa/input.json',
                            'src/reports/opa/opa-debug.txt',
                            'src/reports/opa/opa-technical-ok.txt',
                            'src/reports/opa/opa-result.txt',
                            'src/reports/sbom/bom.json',
                            'src/reports/sbom/bom.xml',
                            'src/reports/dashboard/security-dashboard.html'
                        ].join(','),
                        allowEmptyArchive: true,
                        fingerprint      : false
                    )
                }
            }

            sh '''
                set +e
                echo "=== POST CLEANUP ==="
                chown -R "$JENKINS_UID:$JENKINS_GID" "$WORKSPACE" 2>/dev/null || true

                docker logout >/dev/null 2>&1 || true
                docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        failure {
            echo 'Pipeline FAILED — consulter les logs et les rapports archivés.'
        }

        unstable {
            echo 'Pipeline UNSTABLE — au moins un scan a rencontré une erreur technique ou a trouvé des problèmes.'
        }

        success {
            echo 'Pipeline SUCCESS — exécution complète et policy OPA validée.'
        }
    }
}
