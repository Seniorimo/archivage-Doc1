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
        booleanParam(name: 'ENFORCE_SECURITY_GATE', defaultValue: false, description: 'Strict mode: fail the build if the OPA security gate does not pass')
        booleanParam(name: 'IGNORE_TEST_APP_FINDINGS', defaultValue: false, description: 'Demo mode: ignore findings from /api/test/devsecops/* endpoints')
    }

    environment {
        APP_NAME         = 'archivage-Doc'
        APP_CONTAINER    = 'app-archivage'
        MYSQL_CONTAINER  = 'mysql-archivage'
        NETWORK_NAME     = 'archivage-net'
        APP_PORT         = '8090'
        PROJECT_DIR      = "${WORKSPACE}/src"
        DOCKER_IMAGE     = "archivage-app:${env.BUILD_NUMBER}"
        MAVEN_REPO       = '/var/jenkins_home/.m2/repository'
        SONARQUBE_ENV    = 'sonar'
        SONAR_DOCKER_URL = 'http://host.docker.internal:9000'
        IGNORE_FINDINGS  = "${params.IGNORE_TEST_APP_FINDINGS}"
    }

    stages {
        stage('Init Env') {
            steps {
                script {
                    env.JENKINS_UID = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID = sh(returnStdout: true, script: 'id -g').trim()
                }
            }
        }

        stage('Init & Clean Workspace') {
            steps {
                sh 'docker run --rm -u 0:0 -v "$WORKSPACE:/ws" alpine:3.19 sh -c "find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true; mkdir -p /ws/src; chown -R ${JENKINS_UID}:${JENKINS_GID} /ws"'
                dir('src') { checkout scm }
                sh '''
                    cd "$PROJECT_DIR"
                    rm -rf reports .jarpath
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa reports/sonar reports/runtime reports/dashboard
                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"
                    
                    # Trivy Volume Cache
                    docker volume create trivy-cache-vol >/dev/null 2>&1 || true
                '''
            }
        }

        stage('Compile & Build Docker Image') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" maven:3.9.9-eclipse-temurin-17 mvn -B -f pom.xml -Dmaven.repo.local="$MAVEN_REPO" clean package -DskipTests
                    find "$PROJECT_DIR/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1 > "$PROJECT_DIR/.jarpath"
                    docker build -t "$DOCKER_IMAGE" .
                '''
            }
        }

        stage('Security Scans') {
            parallel {
                stage('Secrets - Gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" zricethezav/gitleaks:latest detect --source . --log-opts="--all" --report-format json --report-path reports/gitleaks/gitleaks-raw.json --exit-code 0 || true
                                docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" -e IGNORE_TEST_APP_FINDINGS="$IGNORE_FINDINGS" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/filter_gitleaks.py || true
                                test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
                                docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_gitleaks_summary.py reports/gitleaks/gitleaks-report.json || true
                            '''
                        }
                    }
                }

                stage('SCA - Trivy Image & FS') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                docker run --rm --user 0:0 -v trivy-cache-vol:/root/.cache/trivy --volumes-from jenkins -w "$PROJECT_DIR" \
                                    ghcr.io/aquasecurity/trivy:latest fs --no-progress --quiet \
                                    --db-repository public.ecr.aws/aquasecurity/trivy-db:2 \
                                    --java-db-repository public.ecr.aws/aquasecurity/trivy-java-db:1 \
                                    --scanners vuln --severity CRITICAL,HIGH,MEDIUM,LOW --format json \
                                    --output reports/trivy/trivy-fs-report.json . 2> reports/trivy/trivy-fs.stderr.log || true
                                
                                docker run --rm --user 0:0 -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache-vol:/root/.cache/trivy --volumes-from jenkins -w "$PROJECT_DIR" \
                                    ghcr.io/aquasecurity/trivy:latest image --no-progress --quiet \
                                    --db-repository public.ecr.aws/aquasecurity/trivy-db:2 \
                                    --java-db-repository public.ecr.aws/aquasecurity/trivy-java-db:1 \
                                    --scanners vuln --severity CRITICAL,HIGH,MEDIUM,LOW --format json \
                                    --output reports/trivy/trivy-report.json "$DOCKER_IMAGE" 2> reports/trivy/trivy.stderr.log || true
                                
                                chown -R "${JENKINS_UID}:${JENKINS_GID}" reports/trivy || true
                                test -s reports/trivy/trivy-report.json || echo '{"Results":[]}' > reports/trivy/trivy-report.json
                                docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_trivy_summary.py reports/trivy/trivy-report.json || true
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            withSonarQubeEnv("sonar") {
                                sh '''
                                    cd "$PROJECT_DIR"
                                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --network "$NETWORK_NAME" --volumes-from jenkins --add-host=host.docker.internal:host-gateway -w "$PROJECT_DIR" maven:3.9.9-eclipse-temurin-17 mvn -B -f pom.xml -Dmaven.repo.local="$MAVEN_REPO" org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar -DskipTests -Dsonar.projectKey="$APP_NAME" -Dsonar.host.url="$SONAR_DOCKER_URL" -Dsonar.login="$SONAR_AUTH_TOKEN" -Dsonar.java.binaries="target/classes" -Dsonar.qualitygate.wait=false || true
                                    docker run --rm --network "$NETWORK_NAME" --volumes-from jenkins --add-host=host.docker.internal:host-gateway -w "$PROJECT_DIR" curlimages/curl:8.7.1 curl -sf -u "$SONAR_AUTH_TOKEN:" "$SONAR_DOCKER_URL/api/issues/search?componentKeys=$APP_NAME&types=VULNERABILITY&severities=BLOCKER,CRITICAL,MAJOR,MINOR,INFO&p=1&ps=100" -o "reports/sonar/sonar-vulnerabilities.json" || echo '{"issues":[],"total":0}' > "reports/sonar/sonar-vulnerabilities.json"
                                    docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_sonar_summary.py reports/sonar/sonar-vulnerabilities.json || true
                                '''
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" maven:3.9.9-eclipse-temurin-17 mvn -B -f pom.xml -Dmaven.repo.local="$MAVEN_REPO" org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all || true
                                cp -f target/bom.xml reports/sbom/bom.xml || true
                                cp -f target/bom.json reports/sbom/bom.json || true
                            '''
                        }
                    }
                }
            }
        }

        stage('Deploy Infrastructure & App') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    docker rm -f "$MYSQL_CONTAINER" "$APP_CONTAINER" >/dev/null 2>&1 || true
                    
                    docker run -d --name "$MYSQL_CONTAINER" --network "$NETWORK_NAME" -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=archivage_doc -e MYSQL_USER=archivage_user -e MYSQL_PASSWORD=archivage_pass mysql:8.0 >/dev/null
                    
                    for i in $(seq 1 30); do
                        if docker exec "$MYSQL_CONTAINER" mysqladmin ping -h 127.0.0.1 -uroot -proot --silent >/dev/null 2>&1; then break; fi
                        sleep 3
                    done

                    mkdir -p "$PROJECT_DIR/uploads"
                    docker run -d --name "$APP_CONTAINER" --network "$NETWORK_NAME" --restart on-failure:5 -v "$PROJECT_DIR/uploads:/app/uploads" -e SPRING_PROFILES_ACTIVE=docker -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" -e SPRING_DATASOURCE_USERNAME="archivage_user" -e SPRING_DATASOURCE_PASSWORD="archivage_pass" -e GITHUB_OAUTH_SECRET="test-secret" -e JWT_SECRET="404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970" "$DOCKER_IMAGE" >/dev/null

                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)
                        if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then exit 0; fi
                        sleep 5
                    done
                '''
            }
        }

        stage('Runtime Security - Falco (Start)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        cd "$PROJECT_DIR"
                        docker rm -f falco-runtime 2>/dev/null || true

                        TRACEFS_PATH="/sys/kernel/tracing"
                        [ -d "/sys/kernel/debug/tracing" ] && TRACEFS_PATH="/sys/kernel/debug/tracing"

                        KVER_MAJOR=$(uname -r | cut -d. -f1)
                        KVER_MINOR=$(uname -r | cut -d. -f2 | cut -d- -f1)
                        echo "[Falco] Pre-flight kernel: $(uname -r)"
                        echo "[Falco] Pre-flight tracefs: ${TRACEFS_PATH}"

                        FALCO_DRIVERS=""
                        if [ "$KVER_MAJOR" -gt 5 ] || { [ "$KVER_MAJOR" -eq 5 ] && [ "$KVER_MINOR" -ge 8 ]; }; then
                            if [ -d "$TRACEFS_PATH" ]; then
                                FALCO_DRIVERS="modern_ebpf"
                                echo "[Falco] Pre-flight: modern_ebpf eligible (kernel >= 5.8, tracefs present)"
                            fi
                        fi
                        if [ -d "$TRACEFS_PATH" ]; then
                            FALCO_DRIVERS="${FALCO_DRIVERS} bpf"
                            echo "[Falco] Pre-flight: bpf eligible (tracefs present)"
                        fi
                        FALCO_DRIVERS="${FALCO_DRIVERS} kmod"
                        echo "[Falco] Pre-flight: driver try order ->${FALCO_DRIVERS}"

                        if [ ! -f "$PROJECT_DIR/ci/falco/custom-rules.yaml" ]; then
                            echo "[WARN] custom-rules.yaml introuvable, Falco démarré sans règles custom"
                            FALCO_RULES_MOUNT=""
                        else
                            FALCO_RULES_MOUNT="-v $PROJECT_DIR/ci/falco/custom-rules.yaml:/etc/falco/rules.d/custom-rules.yaml:ro"
                        fi

                        FALCO_STARTED=0
                        for DRIVER in $FALCO_DRIVERS; do
                            docker rm -f falco-runtime 2>/dev/null || true
                            case "$DRIVER" in
                                modern_ebpf) DRIVER_ARGS="--modern-bpf" ;;
                                bpf)         DRIVER_ARGS="--bpf" ;;
                                kmod)        DRIVER_ARGS="" ;;
                            esac
                            echo "[Falco] Starting with driver=${DRIVER} args='${DRIVER_ARGS}'"
                            docker run -d --name falco-runtime \
                                --privileged \
                                -v "${TRACEFS_PATH}:/sys/kernel/tracing:ro" \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v /proc:/host/proc:ro \
                                -v /etc:/host/etc:ro \
                                ${FALCO_RULES_MOUNT} \
                                falcosecurity/falco:0.44.0 falco ${DRIVER_ARGS} \
                                --option "json_output=true" \
                                --option "log_level=info" || true

                            READY=0
                            for i in $(seq 1 15); do
                                if ! docker ps -q -f name=falco-runtime | grep -q .; then
                                    echo "[WARN] Falco container died with driver ${DRIVER}"
                                    break
                                fi
                                if docker logs falco-runtime 2>&1 | grep -qE "Falco initialized|Starting internal|inotify"; then
                                    READY=1
                                    break
                                fi
                                sleep 2
                            done

                            if [ "$READY" -eq 1 ]; then
                                echo "[Falco] Ready with driver: ${DRIVER}"
                                FALCO_STARTED=1
                                break
                            fi
                            echo "[WARN] Driver ${DRIVER} failed readiness, trying next..."
                        done

                        if [ "$FALCO_STARTED" -eq 0 ]; then
                            echo "[ERROR] Falco could not start with any driver (modern_ebpf / bpf / kmod)"
                        fi

                        echo "--- Falco startup logs (first 20 lines) ---"
                        docker logs falco-runtime 2>&1 | head -20 || true
                    '''
                }
            }
        }

        stage('DAST - OWASP ZAP (Attack)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        cd "$PROJECT_DIR"
                        mkdir -p reports/zap
                        chmod 777 reports/zap

                        ZAP_VOL="zap-reports-$$"
                        docker volume create "$ZAP_VOL" >/dev/null

                        docker run --rm --user root --network "$NETWORK_NAME" -e HOME=/zap -v "${ZAP_VOL}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable bash -c '
                            set -o pipefail
                            umask 0002
                            zap-baseline.py -t "http://app-archivage:8090/" -J zap-report.json -r zap-report.html -a -I 2>&1 | tee /zap/wrk/zap-baseline.log
                            echo ${PIPESTATUS[0]} > /zap/wrk/zap-exit-code.txt
                            chown -R '"${JENKINS_UID}:${JENKINS_GID}"' /zap/wrk || true
                        ' || true

                        docker run --rm --volumes-from jenkins -v "${ZAP_VOL}:/zap/wrk:ro" alpine:3.19 sh -c "cp -f /zap/wrk/* $PROJECT_DIR/reports/zap/ 2>/dev/null || true"
                        docker volume rm "$ZAP_VOL" >/dev/null 2>&1 || true

                        test -s "reports/zap/zap-report.json" || echo '{"site":[{"alerts":[]}]}' > "reports/zap/zap-report.json"
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" -e IGNORE_TEST_APP_FINDINGS="$IGNORE_FINDINGS" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/filter_zap.py || true
                        docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_zap_summary.py reports/zap/zap-report.filtered.json || true
                    '''
                }
            }
        }

        stage('Runtime Security - Falco (Resolve Target)') {
            steps {
                sh '''
                    cd "$PROJECT_DIR"
                    mkdir -p reports/runtime
                    docker inspect --format '{{.Id}}' "$APP_CONTAINER" > reports/runtime/app-container-id.txt 2>/dev/null || echo "" > reports/runtime/app-container-id.txt
                    CID_SHORT=$(head -c 12 reports/runtime/app-container-id.txt 2>/dev/null | tr -d '\n' || true)
                    echo "[Falco] Target container: ${APP_CONTAINER} (ID prefix: ${CID_SHORT:-unknown})"
                '''
            }
        }

        stage('Runtime Security - Falco (Collect)') {
            steps {
                sh '''
                    cd "$PROJECT_DIR"
                    mkdir -p reports/runtime

                    docker logs falco-runtime 2>&1 | grep -E '^\\{' > reports/runtime/falco-raw.json || true
                    touch reports/runtime/falco-raw.json

                    echo "[DEBUG] Container IDs in falco-raw.json:"
                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine \
                        python3 -c "
import json, collections
from pathlib import Path
raw = Path('reports/runtime/falco-raw.json')
events = []
if raw.exists() and raw.stat().st_size > 0:
    for line in raw.read_text(encoding='utf-8-sig', errors='replace').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
ids = collections.Counter(
    (e.get('output_fields') or {}).get('container.id') or '<none>'
    for e in events
)
print(f'[DEBUG] Total raw events: {len(events)}')
for cid, cnt in ids.most_common():
    print(f'  {cid}: {cnt} events')
" || true

                    echo "[DEBUG] app-archivage container ID (from docker inspect):"
                    docker inspect --format '{{.Id}}' "$APP_CONTAINER" 2>/dev/null | cut -c1-12 || echo "  (inspect failed)"
                    if [ -f reports/runtime/app-container-id.txt ]; then
                        echo "[DEBUG] app-container-id.txt (saved at resolve stage):"
                        cut -c1-12 reports/runtime/app-container-id.txt | sed 's/^/  /' || true
                    fi

                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine \
                        python3 ci/scripts/parse_falco.py \
                        reports/runtime/falco-raw.json \
                        reports/runtime/falco-alerts.json \
                        "${APP_CONTAINER}" \
                        reports/runtime/app-container-id.txt || echo "[]" > reports/runtime/falco-alerts.json

                    ALERT_COUNT=$(docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine \
                        python3 -c "import json; print(len(json.load(open('reports/runtime/falco-alerts.json', encoding='utf-8-sig'))))" 2>/dev/null || echo 0)

                    echo "======================================================"
                    echo "   FALCO RUNTIME SECURITY — ZAP PHASE SUMMARY"
                    echo "======================================================"
                    echo "Falco alerts on ${APP_CONTAINER}: ${ALERT_COUNT}"
                    if [ "${ALERT_COUNT}" != "0" ]; then
                        echo "Sample (first event output):"
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine \
                            python3 -c "import json; evts=json.load(open('reports/runtime/falco-alerts.json', encoding='utf-8-sig')); print('  ' + (evts[0].get('output','')[:200] if evts else ''))" 2>/dev/null || true
                    fi
                    echo "======================================================"
                '''
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh """
                    cd "\$PROJECT_DIR"

                    docker run --rm --user "\${JENKINS_UID}:\${JENKINS_GID}" -e ENFORCE_GATE="${params.ENFORCE_SECURITY_GATE}" --volumes-from jenkins -w "\$PROJECT_DIR" python:3.12-alpine python ci/scripts/build_input.py || true

                    docker run --rm --volumes-from jenkins -w "\$PROJECT_DIR" openpolicyagent/opa:latest eval --format pretty --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security" | tee "reports/opa/opa-debug.txt" || true
                    docker run --rm --volumes-from jenkins -w "\$PROJECT_DIR" openpolicyagent/opa:latest eval --format raw --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security.allow" > "reports/opa/opa-result.txt" || true
                    docker run --rm --volumes-from jenkins -w "\$PROJECT_DIR" openpolicyagent/opa:latest eval --format raw --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security.thresholds_ok" > "reports/opa/opa-thresholds.txt" || true
                """

                script {
                    def allowOk = sh(script: 'cat "$PROJECT_DIR/reports/opa/opa-result.txt" || echo "false"', returnStdout: true).trim()
                    def thresholdsOk = sh(script: 'cat "$PROJECT_DIR/reports/opa/opa-thresholds.txt" || echo "false"', returnStdout: true).trim()

                    if (allowOk != "true") {
                        error("OPA SECURITY GATE : FAILED (Strict Mode ON - Critical/High Vulnerabilities detected)")
                    } else if (thresholdsOk != "true") {
                        unstable("SECURITY VULNERABILITIES DETECTED : Build marked UNSTABLE (Strict Mode OFF - Demo Mode)")
                    } else {
                        echo "OPA SECURITY GATE : PASSED (No blocking vulnerabilities)"
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                withSonarQubeEnv("sonar") {
                    sh '''
                        set +e
                        cd "$PROJECT_DIR"
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --network "$NETWORK_NAME" --volumes-from jenkins --add-host=host.docker.internal:host-gateway -e SONAR_HOST_URL="$SONAR_DOCKER_URL" -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" -w "$PROJECT_DIR" python:3.12-alpine python generate_dashboard.py --reports reports --output reports/dashboard/security-dashboard.html --project "$APP_NAME" --sonar-url "$SONAR_DOCKER_URL" --sonar-token "$SONAR_AUTH_TOKEN" --sonar-project "$APP_NAME" || true
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/patch_csp.py reports/dashboard/security-dashboard.html || true
                    '''
                }
            }

            sh '''
                set +e
                docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" falco-runtime >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
                docker run --rm -u 0:0 -v "$WORKSPACE:/ws" alpine:3.19 sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null || true"
            '''

            script {
                if (fileExists('src/reports/zap/zap-report.html')) {
                    publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'src/reports/zap', reportFiles: 'zap-report.html', reportName: 'ZAP Web Report'])
                }
                if (fileExists('src/reports/dashboard/security-dashboard.html')) {
                    publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'src/reports/dashboard', reportFiles: 'security-dashboard.html', reportName: 'Security Dashboard'])
                }
                
                if (fileExists('src/reports')) {
                    archiveArtifacts(
                        artifacts: [
                            'src/reports/gitleaks/gitleaks-raw.json',
                            'src/reports/gitleaks/gitleaks-report.json',
                            'src/reports/trivy/trivy-report.json',
                            'src/reports/trivy/trivy.stderr.log',
                            'src/reports/trivy/trivy-fs-report.json',
                            'src/reports/trivy/trivy-fs.stderr.log',
                            'src/reports/zap/zap-baseline.log',
                            'src/reports/zap/zap-exit-code.txt',
                            'src/reports/zap/zap-report.html',
                            'src/reports/zap/zap-report.json',
                            'src/reports/zap/zap-report.filtered.json',
                            'src/reports/runtime/app-container-id.txt',
                            'src/reports/runtime/falco-raw.json',
                            'src/reports/runtime/falco-alerts.json',
                            'src/reports/runtime/falco-alerts.txt',
                            'src/reports/opa/opa-result.txt',
                            'src/reports/opa/opa-thresholds.txt',
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
        }

        failure { echo 'Pipeline FAILED - Veuillez vérifier les rapports de sécurité.' }
        unstable { echo 'Pipeline UNSTABLE - Vulnérabilités tolérées en mode non-bloquant.' }
        success { echo 'Pipeline SUCCESS - Toutes les barrières de sécurité sont passées.' }
    }
}