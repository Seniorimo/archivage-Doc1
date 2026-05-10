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
                    env.TRIVY_CACHE = "${env.WORKSPACE}/src/.trivycache"
                    env.JENKINS_UID = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID = sh(returnStdout: true, script: 'id -g').trim()
                }
            }
        }

        // ── 2. FORCE CLEAN WORKSPACE ─────────────────────────────────────────
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
                    echo "Workspace nettoyé de force avec succès."
                '''
            }
        }

        // ── 3. CHECKOUT ──────────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                dir('src') {
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
                    echo "Commit checkouté : ${env.GIT_SHA}"
                }
            }
        }

        // ── 4. LOGIN & PULL IMAGE ────────────────────────────────────────────
stage('Login & Pull Image') {
    steps {
        withCredentials([usernamePassword(
            credentialsId: 'docker-hub-creds',
            usernameVariable: 'DOCKER_HUB_USERNAME',
            passwordVariable: 'DOCKER_HUB_PASSWORD'
        )]) {
            script {
                def repoName = 'archivage-app'

                env.RESOLVED_IMAGE_TAG = sh(
                    returnStdout: true,
                    script: '''
                        set -euo pipefail

                        REPO="${DOCKER_HUB_USERNAME}/archivage-app"

                        TOKEN=$(curl -fsSL \
                          -H "Content-Type: application/json" \
                          -X POST \
                          -d "{\"username\":\"$DOCKER_HUB_USERNAME\",\"password\":\"$DOCKER_HUB_PASSWORD\"}" \
                          https://hub.docker.com/v2/users/login/ \
                          | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

                        TAG=$(curl -fsSL \
                          -H "Authorization: JWT $TOKEN" \
                          "https://hub.docker.com/v2/repositories/$REPO/tags?page_size=25&ordering=-last_updated" \
                          | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('results', [])
tags = [t.get('name','') for t in results if t.get('name') and t.get('name') != 'latest']
print(tags[0] if tags else '')
")

                        if [ -z "$TAG" ]; then
                          echo "ERROR: aucun tag exploitable trouvé sur Docker Hub" >&2
                          exit 1
                        fi

                        echo "$TAG"
                    '''
                ).trim()

                env.DOCKER_IMAGE = "${env.DOCKER_HUB_USERNAME}/${repoName}:${env.RESOLVED_IMAGE_TAG}"

                echo "IMAGE_TAG récupéré automatiquement depuis Docker Hub : ${env.RESOLVED_IMAGE_TAG}"
                echo "Image cible : ${env.DOCKER_IMAGE}"
            }

            sh '''
                set -eu
                echo "=== LOGIN & PULL IMAGE ==="
                echo "$DOCKER_HUB_PASSWORD" | docker login -u "$DOCKER_HUB_USERNAME" --password-stdin
                docker pull "$DOCKER_IMAGE"
                echo "Image récupérée : $DOCKER_IMAGE"
            '''
        }
    }
}

        // ── 5. PREPARE WORKSPACE ─────────────────────────────────────────────
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

                    if [ -f generate_dashboard.py ]; then
                        chmod +x generate_dashboard.py || true
                        echo "Dashboard script détecté : generate_dashboard.py"
                    else
                        echo "[WARN] Script dashboard absent : generate_dashboard.py"
                    fi

                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

allow if {
    input.trivy.critical == 0
    count(input.gitleaks) == 0
    input.zap.high == 0
}
REGO

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
    "trivy": {
        "critical": sev["CRITICAL"],
        "high":     sev["HIGH"],
        "medium":   sev["MEDIUM"],
        "low":      sev["LOW"]
    },
    "zap": {"high": zap_high}
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(
    json.dumps(payload, indent=2), encoding="utf-8"
)

print("=== OPA INPUT SUMMARY ===")
print("  Gitleaks secrets : " + str(len(payload["gitleaks"])))
print("  Trivy CRITICAL   : " + str(sev["CRITICAL"]))
print("  Trivy HIGH       : " + str(sev["HIGH"]))
print("  ZAP HIGH         : " + str(zap_high))
print("=========================")
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

all_alerts.sort(key=lambda a: -int(a.get("riskcode", 0)))

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
      {rows if rows else '<tr><td colspan="4" style="text-align:center;padding:30px;color:#27ae60"><strong>Aucune alerte détectée</strong></td></tr>'}
    </tbody>
  </table>
</body>
</html>"""

out.write_text(html, encoding="utf-8")
print("Rapport HTML ZAP généré : " + str(out))
ZAPEOF

                    cat > reports/dashboard/patch_csp.py <<'PYEOF'
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

                    echo "Workspace préparé avec succès."
                '''
            }
        }

        // ── 6. COMPILE LIGHT ────────────────────────────────────────────────
        stage('Compile Light') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== COMPILE LIGHT ==="
                    docker run --rm \
                        --user "${JENKINS_UID}:${JENKINS_GID}" \
                        --volumes-from jenkins \
                        -w "$PROJECT_DIR" \
                        maven:3.9.9-eclipse-temurin-17 \
                        sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                    -Dmaven.repo.local='$MAVEN_REPO' \
                                    clean compile -DskipTests"
                '''
            }
        }

        // ── 7. SECURITY SCANS (parallel) ─────────────────────────────────────
        stage('Security Scans') {
            parallel {

                stage('Secrets - Gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                docker run --rm \
                                    --volumes-from jenkins \
                                    -w "$PROJECT_DIR" \
                                    zricethezav/gitleaks:latest detect \
                                        --source . \
                                        --log-opts="--all" \
                                        --report-format json \
                                        --report-path reports/gitleaks/gitleaks-report.json \
                                        --exit-code 0

                                test -s reports/gitleaks/gitleaks-report.json \
                                    || echo "[]" > reports/gitleaks/gitleaks-report.json
                            '''
                        }
                    }
                }

                stage('SCA - Trivy Image') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$PROJECT_DIR/reports/trivy:/reports" \
                                    -v "$TRIVY_CACHE:/root/.cache/trivy" \
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
                                        set -eu
                                        cd "$PROJECT_DIR"
                                        test -d "$PROJECT_DIR/target/classes"

                                        docker run --rm \
                                            --user "${JENKINS_UID}:${JENKINS_GID}" \
                                            --network "$NETWORK_NAME" \
                                            --volumes-from jenkins \
                                            --add-host=host.docker.internal:host-gateway \
                                            -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                            -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                            -w "$PROJECT_DIR" \
                                            maven:3.9.9-eclipse-temurin-17 \
                                            sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                                        -Dmaven.repo.local='$MAVEN_REPO' \
                                                        org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                                        -Dsonar.projectKey='$APP_NAME' \
                                                        -Dsonar.host.url='$SONAR_HOST_URL' \
                                                        -Dsonar.token='$SONAR_AUTH_TOKEN' \
                                                        -Dsonar.java.binaries='target/classes'"
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
                                docker run --rm \
                                    --user "${JENKINS_UID}:${JENKINS_GID}" \
                                    --volumes-from jenkins \
                                    -w "$PROJECT_DIR" \
                                    maven:3.9.9-eclipse-temurin-17 \
                                    sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                                -Dmaven.repo.local='$MAVEN_REPO' \
                                                org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                                                -DoutputFormat=all"

                                test -f "$PROJECT_DIR/target/bom.xml" \
                                    && cp -f "$PROJECT_DIR/target/bom.xml" "$PROJECT_DIR/reports/sbom/bom.xml" || true
                                test -f "$PROJECT_DIR/target/bom.json" \
                                    && cp -f "$PROJECT_DIR/target/bom.json" "$PROJECT_DIR/reports/sbom/bom.json" || true
                            '''
                        }
                    }
                }

            }
        }

        // ── 8. DEPLOY MYSQL ──────────────────────────────────────────────────
        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eu
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
                        sleep 5
                    done

                    test "$READY" -eq 1 || { echo "MySQL ne répond pas après 30 tentatives."; exit 1; }
                    sleep 10
                '''
            }
        }

        // ── 9. DEPLOY APP ────────────────────────────────────────────────────
        stage('Deploy App') {
            steps {
                sh '''
                    set -eu
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
                        -e GITHUB_OAUTH_SECRET="${GITHUB_OAUTH_SECRET:-test}" \
                        -e JWT_SECRET="${JWT_SECRET:-test}" \
                        "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                               -s -o /dev/null -w "%{http_code}" \
                               "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)
                        if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then
                            READY=1
                            break
                        fi
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        docker logs "$APP_CONTAINER" --tail 200 || true
                        exit 1
                    fi
                '''
            }
        }

        // ── 10. DAST - OWASP ZAP ─────────────────────────────────────────────
        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eu
                        cd "$PROJECT_DIR"

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
                    '''
                }
            }
        }

        // ── 11. POLICY - OPA SECURITY GATE ──────────────────────────────────
        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eu

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
                            "data.security.allow" \
                        > "$PROJECT_DIR/reports/opa/opa-result.txt"

                    cat "$PROJECT_DIR/reports/opa/opa-result.txt"

                    if ! grep -qx "true" "$PROJECT_DIR/reports/opa/opa-result.txt"; then
                        exit 1
                    fi
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
                            cd "$PROJECT_DIR"
                            mkdir -p reports/dashboard
                            docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 \
                                || docker network create "$NETWORK_NAME" >/dev/null 2>&1 || true

                            docker run --rm \
                                --network "$NETWORK_NAME" \
                                --volumes-from jenkins \
                                --add-host=host.docker.internal:host-gateway \
                                -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                -w "$PROJECT_DIR" \
                                python:3.12-alpine \
                                python generate_dashboard.py \
                                    --reports reports \
                                    --output reports/dashboard/security-dashboard.html \
                                    --project "$APP_NAME" \
                                    --sonar-url "$SONAR_HOST_URL" \
                                    --sonar-token "$SONAR_AUTH_TOKEN" \
                                    --sonar-project "$APP_NAME" || true

                            docker run --rm \
                                --volumes-from jenkins \
                                -w "$PROJECT_DIR" \
                                python:3.12-alpine \
                                python reports/dashboard/patch_csp.py \
                                    reports/dashboard/security-dashboard.html \
                                    reports/zap/zap-report.html || true
                        '''
                    }
                } else {
                    sh '''
                        set +e
                        cd "$PROJECT_DIR"
                        docker run --rm \
                            --volumes-from jenkins \
                            -w "$PROJECT_DIR" \
                            python:3.12-alpine \
                            python reports/dashboard/patch_csp.py \
                                reports/dashboard/security-dashboard.html \
                                reports/zap/zap-report.html || true
                    '''
                }
            }

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
                        fingerprint      : true
                    )
                }
            }

            sh '''
                set +e
                docker logout >/dev/null 2>&1 || true
                docker rm -f "$APP_CONTAINER"   >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        failure {
            echo 'Pipeline FAILED — consulter les logs de scan et les rapports archivés.'
        }

        unstable {
            echo 'Pipeline UNSTABLE — des problèmes de sécurité ont été détectés.'
        }

        success {
            echo 'Pipeline SUCCESS — tous les security gates sont passés.'
        }
    }
}
