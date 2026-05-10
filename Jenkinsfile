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
        APP_NAME                  = 'archivage-Doc'
        APP_CONTAINER             = 'app-archivage'
        MYSQL_CONTAINER           = 'mysql-archivage'
        NETWORK_NAME              = 'archivage-net'
        APP_PORT                  = '8090'
        MAVEN_REPO                = '/var/jenkins_home/.m2/repository'
        SONARQUBE_ENV             = 'sonar'
        JENKINS_CONTAINER         = 'jenkins'

        ENFORCE_SECURITY_GATE     = 'false'
        IGNORE_TEST_APP_FINDINGS  = 'false'
    }

    stages {

        stage('Init') {
            steps {
                script {
                    env.PROJECT_DIR = "${env.WORKSPACE}/src"
                    env.TRIVY_CACHE = "/var/jenkins_home/.trivycache"
                    env.JENKINS_UID = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID = sh(returnStdout: true, script: 'id -g').trim()
                }
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
                        sh -euxc "
                            find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
                            mkdir -p /ws/src
                            chown -R ${JENKINS_UID}:${JENKINS_GID} /ws
                            ls -la /ws
                        "
                '''
            }
        }

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
                    env.GIT_SHORT_SHA = env.GIT_SHA.take(7)
                    echo "Commit checkouté : ${env.GIT_SHA}"
                }
            }
        }

        stage('Resolve & Pull Image') {
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
                                  -e DOCKER_HUB_USERNAME="$DOCKER_HUB_USERNAME" \
                                  -e DOCKER_HUB_PASSWORD="$DOCKER_HUB_PASSWORD" \
                                  -e GIT_SHA="$GIT_SHA" \
                                  python:3.12-alpine \
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
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
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
    if candidate in tags:
        print(candidate)
        sys.exit(0)

print(
    f"ERREUR: tag exact introuvable sur Docker Hub pour ce commit. attendus: {git_sha} ou {short_sha}",
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

                        echo "Tag image exact : ${env.RESOLVED_IMAGE_TAG}"
                        echo "Image cible     : ${env.DOCKER_IMAGE}"
                    }

                    sh '''
                        set -eu
                        echo "=== LOGIN & PULL IMAGE ==="
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
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== PREPARE WORKSPACE ==="

                    rm -rf reports policy
                    mkdir -p \
                        reports/gitleaks \
                        reports/trivy \
                        reports/sbom \
                        reports/zap \
                        reports/opa \
                        reports/dashboard \
                        policy

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 \
                        || docker network create "$NETWORK_NAME"

                    if [ -f generate_dashboard.py ]; then
                        chmod +x generate_dashboard.py || true
                    fi

                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

strict_mode if {
    input.settings.enforce_gate == true
}

scans_ok if {
    input.scan_status.gitleaks == "ok"
    input.scan_status.trivy == "ok"
    input.scan_status.zap == "ok"
}

thresholds_ok if {
    count(input.gitleaks) == 0
    input.trivy.critical == 0
    input.zap.high == 0
}

allow if {
    scans_ok
    not strict_mode
}

allow if {
    scans_ok
    strict_mode
    thresholds_ok
}
REGO

                    cat > reports/gitleaks/filter_gitleaks.py <<'PYEOF'
import json
import os
from pathlib import Path

raw = Path("reports/gitleaks/gitleaks-raw.json")
out = Path("reports/gitleaks/gitleaks-report.json")

ignore_test_app_findings = os.environ.get("IGNORE_TEST_APP_FINDINGS", "true").lower() == "true"

if not raw.exists() or raw.stat().st_size == 0:
    out.write_text("[]", encoding="utf-8")
    print("Aucun rapport brut Gitleaks, rapport final vide.")
    raise SystemExit(0)

data = json.loads(raw.read_text(encoding="utf-8"))
filtered = []

for item in data:
    rule = item.get("RuleID")
    path = item.get("File")

    if ignore_test_app_findings:
        if path == "src/main/resources/application.properties":
            continue
        if path == "Jenkinsfile" and rule == "curl-auth-user":
            continue

    filtered.append(item)

out.write_text(json.dumps(filtered, indent=2), encoding="utf-8")
print(f"Gitleaks raw={len(data)} filtered={len(filtered)}")
PYEOF

                    cat > reports/opa/build_input.py <<'PYEOF'
import json
import os
from pathlib import Path

def load_json(path_str, default):
    p = Path(path_str)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

scan_status = {
    "gitleaks": "missing",
    "trivy": "missing",
    "zap": "missing"
}

gitleaks = load_json("reports/gitleaks/gitleaks-report.json", None)
if isinstance(gitleaks, list):
    scan_status["gitleaks"] = "ok"
else:
    gitleaks = []

trivy = load_json("reports/trivy/trivy-report.json", None)
if isinstance(trivy, dict) and isinstance(trivy.get("Results", []), list):
    scan_status["trivy"] = "ok"
else:
    trivy = {"Results": []}

zap = load_json("reports/zap/zap-report.json", None)
if isinstance(zap, dict) and isinstance(zap.get("site", []), list):
    scan_status["zap"] = "ok"
else:
    zap = {"site": [{"alerts": []}]}

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in trivy.get("Results", []) or []:
    for v in result.get("Vulnerabilities", []) or []:
        s = (v.get("Severity") or "").upper()
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
    "settings": {
        "enforce_gate": os.environ.get("ENFORCE_SECURITY_GATE", "false").lower() == "true"
    },
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
Path("reports/opa/input.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

print("=== OPA INPUT SUMMARY ===")
print("scan_status        :", scan_status)
print("enforce_gate       :", payload["settings"]["enforce_gate"])
print("gitleaks findings  :", len(gitleaks))
print("trivy critical     :", sev["CRITICAL"])
print("trivy high         :", sev["HIGH"])
print("trivy medium       :", sev["MEDIUM"])
print("trivy low          :", sev["LOW"])
print("zap high           :", zap_counts["high"])
print("zap medium         :", zap_counts["medium"])
print("zap low            :", zap_counts["low"])
print("zap info           :", zap_counts["info"])
PYEOF

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
    nl = chr(10)
    if "<head>" in html:
        html = html.replace("<head>", "<head>" + nl + "  " + META, 1)
    else:
        html = META + nl + html
    p.write_text(html, encoding="utf-8")
    print(f"[OK] CSP ajoutée : {p}")

for target in sys.argv[1:]:
    patch(target)
PYEOF
                '''
            }
        }

        stage('Compile Light') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    docker run --rm \
                        --user "${JENKINS_UID}:${JENKINS_GID}" \
                        -e HOME=/tmp \
                        --volumes-from "$JENKINS_CONTAINER" \
                        -w "$PROJECT_DIR" \
                        maven:3.9.9-eclipse-temurin-17 \
                        sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                    -Dmaven.repo.local='$MAVEN_REPO' \
                                    clean compile -DskipTests"
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

                                rm -f reports/gitleaks/gitleaks-raw.json reports/gitleaks/gitleaks-report.json

                                docker run --rm \
                                    --volumes-from "$JENKINS_CONTAINER" \
                                    -w "$PROJECT_DIR" \
                                    zricethezav/gitleaks:latest detect \
                                        --source . \
                                        --log-opts="--all" \
                                        --report-format json \
                                        --report-path "$PROJECT_DIR/reports/gitleaks/gitleaks-raw.json" \
                                        --exit-code 0

                                docker run --rm \
                                    -e IGNORE_TEST_APP_FINDINGS="$IGNORE_TEST_APP_FINDINGS" \
                                    --volumes-from "$JENKINS_CONTAINER" \
                                    -w "$PROJECT_DIR" \
                                    python:3.12-alpine \
                                    python reports/gitleaks/filter_gitleaks.py

                                docker run --rm \
                                    -u 0:0 \
                                    -v "$PROJECT_DIR/reports/gitleaks:/reports" \
                                    alpine:3.19 \
                                    sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /reports || true"

                                test -f reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
                                test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
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

                                test -S /var/run/docker.sock \
                                    || { echo "[ERREUR] /var/run/docker.sock absent"; exit 1; }

                                docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1 \
                                    || { echo "[ERREUR] Image absente localement : $DOCKER_IMAGE"; exit 1; }

                                mkdir -p reports/trivy
                                rm -f reports/trivy/trivy-report.json reports/trivy/trivy.stderr.log

                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$TRIVY_CACHE:/root/.cache/trivy" \
                                    ghcr.io/aquasecurity/trivy:latest image \
                                        --quiet \
                                        --scanners vuln \
                                        --severity CRITICAL,HIGH,MEDIUM,LOW \
                                        --format json \
                                        "$DOCKER_IMAGE" \
                                    > reports/trivy/trivy-report.json \
                                    2> reports/trivy/trivy.stderr.log

                                test -s reports/trivy/trivy-report.json \
                                    || { echo "[ERREUR] trivy-report.json vide"; exit 1; }
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
                                            -e HOME=/tmp \
                                            --network "$NETWORK_NAME" \
                                            --volumes-from "$JENKINS_CONTAINER" \
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
                                    -e HOME=/tmp \
                                    --volumes-from "$JENKINS_CONTAINER" \
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

        stage('Deploy App') {
            steps {
                sh '''
                    set -eu
                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                    mkdir -p "$PROJECT_DIR/uploads"

                    _GITHUB_SECRET="${GITHUB_OAUTH_SECRET:-changeme-github}"
                    _JWT_SECRET="${JWT_SECRET:-changeme-jwt-secret-32chars-min}"

                    docker run -d \
                        --name "$APP_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        --restart on-failure:5 \
                        -v "$PROJECT_DIR/uploads:/app/uploads" \
                        -e SPRING_PROFILES_ACTIVE=docker \
                        -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" \
                        -e SPRING_DATASOURCE_USERNAME="archivage_user" \
                        -e SPRING_DATASOURCE_PASSWORD="archivage_pass" \
                        -e GITHUB_OAUTH_SECRET="$_GITHUB_SECRET" \
                        -e JWT_SECRET="$_JWT_SECRET" \
                        "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                               -s -o /dev/null -w "%{http_code}" \
                               "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)
                        echo "HTTP=$CODE"
                        if echo "$CODE" | grep -qE "^(200|301|302|401|403|404)$"; then
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

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eu
                        cd "$PROJECT_DIR"

                        mkdir -p reports/zap
                        rm -f reports/zap/zap-baseline.log \
                              reports/zap/zap-exit-code.txt \
                              reports/zap/zap-report.json \
                              reports/zap/zap-report.html

                        TARGET_URL="http://$APP_CONTAINER:$APP_PORT/"

                        # Créer un volume Docker nommé et y copier rien (juste init)
                        # Puis lancer ZAP qui écrit dans ce volume
                        # Enfin copier les résultats depuis le volume vers reports/zap
                        ZAP_VOL="zap-reports-$$"
                        docker volume create "$ZAP_VOL" >/dev/null

                        docker run --rm \
                            --user root \
                            --network "$NETWORK_NAME" \
                            -v "${ZAP_VOL}:/zap/wrk:rw" \
                            -e HOME=/zap \
                            ghcr.io/zaproxy/zaproxy:stable \
                            bash -c '
                                status=0
                                zap-baseline.py \
                                    -t "'"$TARGET_URL"'" \
                                    -a -I \
                                    -J zap-report.json \
                                    -r zap-report.html \
                                    2>&1 | tee /zap/wrk/zap-baseline.log
                                echo "$?" > /zap/wrk/zap-exit-code.txt
                                exit 0
                            ' || true

                        # Copier les fichiers du volume vers le workspace Jenkins
                        docker run --rm \
                            --volumes-from "$JENKINS_CONTAINER" \
                            -v "${ZAP_VOL}:/zap/wrk:ro" \
                            alpine:3.19 \
                            sh -c "cp -f /zap/wrk/* $PROJECT_DIR/reports/zap/ 2>/dev/null || true"

                        docker volume rm "$ZAP_VOL" >/dev/null 2>&1 || true

                        test -s reports/zap/zap-baseline.log \
                            || { echo "[ERREUR] zap-baseline.log absent ou vide"; exit 1; }

                        echo "ZAP exit code : $(cat reports/zap/zap-exit-code.txt)"

                        test -s reports/zap/zap-report.json \
                            || echo '{"site":[{"@name":"baseline-scan","alerts":[]}]}' \
                               > reports/zap/zap-report.json

                        if [ ! -s reports/zap/zap-report.html ]; then
                            echo "<html><body><p>Aucune alerte ZAP détectée.</p></body></html>" \
                                > reports/zap/zap-report.html
                        fi
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eu
                        cd "$PROJECT_DIR"

                        docker run --rm \
                            -e ENFORCE_SECURITY_GATE="$ENFORCE_SECURITY_GATE" \
                            --volumes-from "$JENKINS_CONTAINER" \
                            -w "$PROJECT_DIR" \
                            python:3.12-alpine \
                            python reports/opa/build_input.py

                        docker run --rm \
                            --volumes-from "$JENKINS_CONTAINER" \
                            -w "$PROJECT_DIR" \
                            openpolicyagent/opa:latest \
                            eval \
                                --format pretty \
                                --data "$PROJECT_DIR/policy/security-gate.rego" \
                                --input "$PROJECT_DIR/reports/opa/input.json" \
                                "data.security" \
                            | tee "$PROJECT_DIR/reports/opa/opa-debug.txt"

                        docker run --rm \
                            --volumes-from "$JENKINS_CONTAINER" \
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
                            echo "[WARN] Security gate non passé"
                            if [ "$ENFORCE_SECURITY_GATE" = "true" ]; then
                                exit 1
                            fi
                        fi
                    '''
                }
            }
        }

        stage('Security Verdict') {
            steps {
                script {
                    if (env.ENFORCE_SECURITY_GATE != 'true') {
                        def findingsStatus = sh(
                            returnStatus: true,
                            script: '''
                                set -eu
                                cd "$PROJECT_DIR"

                                docker run --rm \
                                    --volumes-from "$JENKINS_CONTAINER" \
                                    -w "$PROJECT_DIR" \
                                    python:3.12-alpine \
                                    python - <<'PY'
import json
from pathlib import Path

p = Path("reports/opa/input.json")
d = json.loads(p.read_text(encoding="utf-8"))

has_findings = (
    len(d.get("gitleaks", [])) > 0 or
    d.get("trivy", {}).get("critical", 0) > 0 or
    d.get("trivy", {}).get("high", 0) > 0 or
    d.get("zap", {}).get("high", 0) > 0
)

raise SystemExit(2 if has_findings else 0)
PY
                            '''
                        )

                        if (findingsStatus == 2) {
                            currentBuild.result = 'UNSTABLE'
                            echo 'Findings de sécurité détectés, build marqué UNSTABLE (gate non strict).'
                        }
                    }
                }
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
                                --volumes-from "$JENKINS_CONTAINER" \
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
                        '''
                    }
                }
            }

            script {
                if (fileExists('src/reports/dashboard/patch_csp.py')) {
                    sh '''
                        set +e
                        cd "$PROJECT_DIR"
                        docker run --rm \
                            --volumes-from "$JENKINS_CONTAINER" \
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
                            'src/reports/gitleaks/gitleaks-raw.json',
                            'src/reports/gitleaks/gitleaks-report.json',
                            'src/reports/trivy/trivy-report.json',
                            'src/reports/trivy/trivy.stderr.log',
                            'src/reports/zap/zap-baseline.log',
                            'src/reports/zap/zap-exit-code.txt',
                            'src/reports/zap/zap-report.html',
                            'src/reports/zap/zap-report.json',
                            'src/reports/opa/opa-result.txt',
                            'src/reports/opa/opa-debug.txt',
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

            sh '''
                set +e
                docker logout >/dev/null 2>&1 || true
                docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        failure {
            echo 'Pipeline FAILED — la chaîne DevSecOps ou le gate OPA a échoué.'
        }

        unstable {
            echo 'Pipeline UNSTABLE — scans exécutés avec findings publiés.'
        }

        success {
            echo 'Pipeline SUCCESS — chaîne DevSecOps validée.'
        }
    }
}
