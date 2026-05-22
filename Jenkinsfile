pipeline {

    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
    }

    parameters {
        booleanParam(
            name: 'ENFORCE_SECURITY_GATE',
            defaultValue: false,
            description: 'Strict mode: fail the build if the OPA security gate does not pass'
        )
        booleanParam(
            name: 'IGNORE_TEST_APP_FINDINGS',
            defaultValue: false,
            description: 'Demo mode: ignore findings from /api/test/devsecops/* endpoints and demo assets'
        )
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

        stage('Docker Access Preflight') {
            steps {
                sh '''
                    set -eu
                    echo "=== DOCKER ACCESS PREFLIGHT ==="

                    if [ "$JENKINS_UID" = "0" ]; then
                        echo "[WARN] Jenkins tourne actuellement en root. Preferer un conteneur Jenkins non-root avec acces au groupe docker."
                    fi

                    command -v docker >/dev/null 2>&1 \
                        || { echo "[ERREUR] Docker CLI absent dans le conteneur Jenkins."; exit 1; }

                    test -x "$(command -v docker)" \
                        || { echo "[ERREUR] Docker CLI present mais non executable par Jenkins."; ls -l "$(command -v docker)"; exit 1; }

                    test -S /var/run/docker.sock \
                        || { echo "[ERREUR] Docker socket absent: /var/run/docker.sock"; exit 1; }

                    docker version >/dev/null 2>&1 \
                        || { echo "[ERREUR] Jenkins ne peut pas utiliser Docker. Verifier le groupe du socket /var/run/docker.sock."; ls -l /var/run/docker.sock; id; exit 1; }

                    docker version --format 'Docker client/server OK: {{.Client.Version}}'
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
                        sh -euxc "
                            find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
                            mkdir -p /ws/src
                            chown -R ${JENKINS_UID}:${JENKINS_GID} /ws
                            chmod -R u+rwX /ws
                            ls -la /ws
                        "
                '''
            }
        }

        stage('Checkout') {
            steps {
                dir('src') {
                    deleteDir()
                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: '*/main']],
                        userRemoteConfigs: [[url: 'https://github.com/Seniorimo/archivage-Doc1.git']],
                        extensions: [
                            [$class: 'CloneOption', shallow: true, depth: 1, noTags: true, timeout: 5]
                        ]
                    ])
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

                    docker run --rm \
                        -u 0:0 \
                        -v "$TRIVY_CACHE:/cache" \
                        alpine:3.19 \
                        sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /cache && chmod -R u+rwX /cache || true"

                    if [ -f generate_dashboard.py ]; then
                        chmod +x generate_dashboard.py || true
                    fi

                    test -f ci/scripts/filter_gitleaks.py || { echo "[ERROR] ci/scripts/filter_gitleaks.py missing"; exit 1; }
                    test -f ci/scripts/filter_zap.py || { echo "[ERROR] ci/scripts/filter_zap.py missing"; exit 1; }
                    test -f ci/scripts/build_input.py || { echo "[ERROR] ci/scripts/build_input.py missing"; exit 1; }
                    test -f ci/scripts/patch_csp.py || { echo "[ERROR] ci/scripts/patch_csp.py missing"; exit 1; }
                    test -f ci/policy/security-gate.rego || { echo "[ERROR] ci/policy/security-gate.rego missing"; exit 1; }
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
                                    --user "${JENKINS_UID}:${JENKINS_GID}" \
                                    --volumes-from "$JENKINS_CONTAINER" \
                                    -w "$PROJECT_DIR" \
                                    zricethezav/gitleaks:v8.18.4 detect \
                                        --source . \
                                        --log-opts="--all" \
                                        --report-format json \
                                        --report-path "$PROJECT_DIR/reports/gitleaks/gitleaks-raw.json" \
                                        --exit-code 0

                                docker run --rm \
                                    --user "${JENKINS_UID}:${JENKINS_GID}" \
                                    -e IGNORE_TEST_APP_FINDINGS="$IGNORE_TEST_APP_FINDINGS" \
                                    --volumes-from "$JENKINS_CONTAINER" \
                                    -w "$PROJECT_DIR" \
                                    python:3.12-alpine \
                                    python ci/scripts/filter_gitleaks.py

                                docker run --rm \
                                    -u 0:0 \
                                    -v "$PROJECT_DIR/reports/gitleaks:/reports" \
                                    alpine:3.19 \
                                    sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /reports && chmod -R u+rwX /reports || true"

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
                                    ghcr.io/aquasecurity/trivy:v0.54.1 image \
                                        --quiet \
                                        --scanners vuln \
                                        --severity CRITICAL,HIGH,MEDIUM,LOW \
                                        --format json \
                                        "$DOCKER_IMAGE" \
                                    > reports/trivy/trivy-report.json \
                                    2> reports/trivy/trivy.stderr.log

                                test -s reports/trivy/trivy-report.json \
                                    || { echo "[ERREUR] trivy-report.json vide"; exit 1; }

                                docker run --rm \
                                    -u 0:0 \
                                    -v "$PROJECT_DIR/reports/trivy:/reports" \
                                    -v "$TRIVY_CACHE:/cache" \
                                    alpine:3.19 \
                                    sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /reports /cache && chmod -R u+rwX /reports /cache || true"
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

                                        : "${SONAR_HOST_URL:?SONAR_HOST_URL absent}"
                                        : "${SONAR_AUTH_TOKEN:?SONAR_AUTH_TOKEN absent}"

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

        stage('Deploy Infrastructure') {
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
                        sleep 5
                    done

                    test "$READY" -eq 1 || { echo "MySQL ne répond pas après 30 tentatives."; exit 1; }
                    echo "MySQL ready"
                    sleep 10
                '''

                sh '''
                    set -eu
                    echo "=== DEPLOY APP ==="
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
                        # Accept only 200 (OK), 301/302 (redirects to login), 401/403 (auth required)
                        # 404 is NOT a valid health state
                        if echo "$CODE" | grep -qE "^(200|301|302|401|403)$"; then
                            READY=1
                            break
                        fi
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        docker logs "$APP_CONTAINER" --tail 200 || true
                        exit 1
                    fi
                    echo "App ready"
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"

                    mkdir -p reports/zap
                    rm -f reports/zap/zap-baseline.log \
                          reports/zap/zap-exit-code.txt \
                          reports/zap/zap-report.json \
                          reports/zap/zap-report.html \
                          reports/zap/zap-report.filtered.json

                    TARGET_URL="http://$APP_CONTAINER:$APP_PORT/"

                    ZAP_VOL="zap-reports-$$"
                    docker volume create "$ZAP_VOL" >/dev/null

                    docker run --rm \
                        --user root \
                        --network "$NETWORK_NAME" \
                        -v "${ZAP_VOL}:/zap/wrk:rw" \
                        -e HOME=/zap \
                        ghcr.io/zaproxy/zaproxy:stable \
                        bash -c '
                            set -o pipefail
                            umask 0002
                            zap-baseline.py \
                                -t "'"$TARGET_URL"'" \
                                -a -I \
                                -J zap-report.json \
                                -r zap-report.html \
                                2>&1 | tee /zap/wrk/zap-baseline.log
                            ZAP_EXIT_CODE=$?
                            echo "$ZAP_EXIT_CODE" > /zap/wrk/zap-exit-code.txt
                            chown -R '"${JENKINS_UID}:${JENKINS_GID}"' /zap/wrk || true
                            chmod -R u+rwX /zap/wrk || true
                            find /zap/wrk -type f -exec chmod u+w {} + || true
                            exit $ZAP_EXIT_CODE
                        ' || true

                    docker run --rm \
                        --volumes-from "$JENKINS_CONTAINER" \
                        -v "${ZAP_VOL}:/zap/wrk:ro" \
                        alpine:3.19 \
                        sh -c "cp -f /zap/wrk/* $PROJECT_DIR/reports/zap/ 2>/dev/null || true"

                    docker volume rm "$ZAP_VOL" >/dev/null 2>&1 || true

                    docker run --rm \
                        -u 0:0 \
                        -v "$PROJECT_DIR/reports/zap:/reports" \
                        alpine:3.19 \
                        sh -c "
                            chown -R ${JENKINS_UID}:${JENKINS_GID} /reports || true
                            chmod -R u+rwX /reports || true
                            find /reports -type f -exec chmod u+w {} + || true
                            find /reports -type d -exec chmod u+rwx {} + || true
                        " || true

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

                    docker run --rm \
                        -u 0:0 \
                        -v "$PROJECT_DIR/reports/zap:/reports" \
                        alpine:3.19 \
                        sh -c "
                            chown -R ${JENKINS_UID}:${JENKINS_GID} /reports || true
                            chmod -R u+rwX /reports || true
                            chmod u+w /reports/*.html /reports/*.json 2>/dev/null || true
                            chmod 664 /reports/zap-report.html 2>/dev/null || true
                        " || true

                    docker run --rm \
                        --user "${JENKINS_UID}:${JENKINS_GID}" \
                        -e IGNORE_TEST_APP_FINDINGS="$IGNORE_TEST_APP_FINDINGS" \
                        --volumes-from "$JENKINS_CONTAINER" \
                        -w "$PROJECT_DIR" \
                        python:3.12-alpine \
                        python ci/scripts/filter_zap.py

                    docker run --rm \
                        -u 0:0 \
                        -v "$PROJECT_DIR/reports/zap:/reports" \
                        alpine:3.19 \
                        sh -c "
                            chown -R ${JENKINS_UID}:${JENKINS_GID} /reports || true
                            chmod -R u+rwX /reports || true
                            chmod u+w /reports/*.* 2>/dev/null || true
                        " || true
                '''
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                script {
                    withSonarQubeEnv("${SONARQUBE_ENV}") {
                        sh '''
                            set -eu
                            cd "$PROJECT_DIR"

                            : "${SONAR_HOST_URL:?SONAR_HOST_URL absent}"
                            : "${SONAR_AUTH_TOKEN:?SONAR_AUTH_TOKEN absent}"

                            mkdir -p reports/opa

                            docker run --rm \
                                --user "${JENKINS_UID}:${JENKINS_GID}" \
                                -e ENFORCE_SECURITY_GATE="$ENFORCE_SECURITY_GATE" \
                                -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                -e APP_NAME="$APP_NAME" \
                                --network "$NETWORK_NAME" \
                                --add-host=host.docker.internal:host-gateway \
                                --volumes-from "$JENKINS_CONTAINER" \
                                -w "$PROJECT_DIR" \
                                python:3.12-alpine \
                                python ci/scripts/build_input.py

                            test -s "$PROJECT_DIR/reports/opa/input.json" \
                                || { echo "[ERREUR] reports/opa/input.json absent ou vide"; exit 1; }

                            docker run --rm \
                                --volumes-from "$JENKINS_CONTAINER" \
                                -w "$PROJECT_DIR" \
                                openpolicyagent/opa:v0.60.0 \
                                eval \
                                    --format pretty \
                                    --data "$PROJECT_DIR/ci/policy/security-gate.rego" \
                                    --input "$PROJECT_DIR/reports/opa/input.json" \
                                    "data.security" \
                                | tee "$PROJECT_DIR/reports/opa/opa-debug.txt"

                            docker run --rm \
                                --volumes-from "$JENKINS_CONTAINER" \
                                -w "$PROJECT_DIR" \
                                openpolicyagent/opa:v0.60.0 \
                                eval \
                                    --format raw \
                                    --data "$PROJECT_DIR/ci/policy/security-gate.rego" \
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
        }

        stage('Security Verdict') {
            steps {
                script {
                    if (!params.ENFORCE_SECURITY_GATE) {
                        def securityVerdict = sh(
                            returnStdout: true,
                            script: '''
                                set -eu
                                cd "$PROJECT_DIR"

                                docker run --rm -i \
                                    --user "${JENKINS_UID}:${JENKINS_GID}" \
                                    --volumes-from "$JENKINS_CONTAINER" \
                                    -w "$PROJECT_DIR" \
                                    python:3.12-alpine \
                                    python - <<'PY'
import json
from pathlib import Path

p = Path("reports/opa/input.json")
d = json.loads(p.read_text(encoding="utf-8"))

scan_status = d.get("scan_status", {})
missing_scans = [
    name for name, status in scan_status.items()
    if status != "ok"
]

has_findings = (
    len(d.get("gitleaks", [])) > 0 or
    d.get("trivy", {}).get("critical", 0) > 0 or
    d.get("trivy", {}).get("high", 0) > 0 or
    d.get("trivy", {}).get("medium", 0) > 0 or
    d.get("trivy", {}).get("low", 0) > 0 or
    d.get("zap", {}).get("high", 0) > 0 or
    d.get("zap", {}).get("medium", 0) > 0 or
    d.get("zap", {}).get("low", 0) > 0
)

if missing_scans:
    print("UNSTABLE: scans manquants -> " + ", ".join(missing_scans))
elif has_findings:
    print(
        "UNSTABLE: findings detectes -> "
        + "gitleaks=" + str(len(d.get("gitleaks", [])))
        + ", trivy="
        + str(d.get("trivy", {}).get("critical", 0)) + "C/"
        + str(d.get("trivy", {}).get("high", 0)) + "H/"
        + str(d.get("trivy", {}).get("medium", 0)) + "M/"
        + str(d.get("trivy", {}).get("low", 0)) + "L"
        + ", zap="
        + str(d.get("zap", {}).get("high", 0)) + "H/"
        + str(d.get("zap", {}).get("medium", 0)) + "M/"
        + str(d.get("zap", {}).get("low", 0)) + "L"
    )
else:
    print("SUCCESS: aucun finding detecte")
PY
                            '''
                        )

                        securityVerdict = securityVerdict.trim()
                        echo securityVerdict

                        if (securityVerdict.startsWith('UNSTABLE:')) {
                            unstable(securityVerdict)
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
                    sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null && chmod -R u+rwX /ws 2>/dev/null || true" || true
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
                                --user "${JENKINS_UID}:${JENKINS_GID}" \
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
                if (fileExists('src/ci/scripts/patch_csp.py')) {
                    sh '''
                        set +e
                        cd "$PROJECT_DIR"

                        docker run --rm \
                            -u 0:0 \
                            -v "$PROJECT_DIR/reports/dashboard:/dashboard" \
                            -v "$PROJECT_DIR/reports/zap:/zap" \
                            alpine:3.19 \
                            sh -c "
                                chown -R ${JENKINS_UID}:${JENKINS_GID} /dashboard /zap 2>/dev/null || true
                                chmod -R u+rwX /dashboard /zap 2>/dev/null || true
                                find /dashboard -type f -exec chmod u+w {} + 2>/dev/null || true
                                find /zap -type f -exec chmod u+w {} + 2>/dev/null || true
                                chmod 664 /zap/zap-report.html 2>/dev/null || true
                            "

                        docker run --rm \
                            --user "${JENKINS_UID}:${JENKINS_GID}" \
                            --volumes-from "$JENKINS_CONTAINER" \
                            -w "$PROJECT_DIR" \
                            python:3.12-alpine \
                            python ci/scripts/patch_csp.py \
                                reports/dashboard/security-dashboard.html || true
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
                            'src/reports/zap/zap-report.filtered.json',
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
