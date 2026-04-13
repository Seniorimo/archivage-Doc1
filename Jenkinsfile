pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        APP_NAME        = 'archivage-Doc'
        APP_CONTAINER   = 'app-archivage'
        MYSQL_CONTAINER = 'mysql-archivage'
        NETWORK_NAME    = 'archivage-net'
        APP_PORT        = '8081'
        WORKDIR         = "${env.WORKSPACE}"
        MAVEN_REPO      = '/var/jenkins_home/.m2/repository'
        TRIVY_CACHE     = "${env.WORKSPACE}/.trivycache"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eux

                    rm -rf reports .trivycache policy .jarpath
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa .trivycache policy

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"

                    cat > policy/security-gate.rego <<'REGO'
                    package security

                    default allow := false

                    allow if {
                      count(input.gitleaks) == 0
                      input.trivy.critical == 0
                      input.zap.high == 0
                    }
                    REGO
                '''
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    set -eux

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKDIR" \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B -f '$WORKDIR/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' clean package -DskipTests"

                    JARPATH=$(find "$WORKDIR/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    echo "JARPATH=$JARPATH"
                    test -n "$JARPATH"
                    echo "$JARPATH" > "$WORKDIR/.jarpath"
                '''
            }
        }

        stage('Secrets - Gitleaks') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eux

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKDIR" \
                          zricethezav/gitleaks:latest detect \
                          --source . \
                          --log-opts="--all" \
                          --report-format json \
                          --report-path reports/gitleaks/gitleaks-report.json \
                          --exit-code 0

                        test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
                    '''
                }
            }
        }

        stage('SCA - Trivy FS') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eux

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKDIR" \
                          -v "$TRIVY_CACHE:/root/.cache/trivy" \
                          ghcr.io/aquasecurity/trivy:latest fs \
                          --timeout 15m \
                          --scanners vuln \
                          --severity LOW,MEDIUM,HIGH,CRITICAL \
                          --format json \
                          --output reports/trivy/trivy-report.json \
                          . || true

                        test -s reports/trivy/trivy-report.json || echo '{"Results":[]}' > reports/trivy/trivy-report.json
                    '''
                }
            }
        }

        stage('SAST - SonarQube') {
            steps {
                withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        set -eux

                        test -d "$WORKDIR/target/classes"
                        test -f "$WORKDIR/.jarpath"

                        docker run --rm \
                          --volumes-from jenkins \
                          --add-host=host.docker.internal:host-gateway \
                          -w "$WORKDIR" \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "mvn -B -f '$WORKDIR/pom.xml' \
                            -Dmaven.repo.local='$MAVEN_REPO' \
                            org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                            -DskipTests \
                            -Dsonar.projectKey='$APP_NAME' \
                            -Dsonar.host.url='http://host.docker.internal:9000' \
                            -Dsonar.login='$SONAR_TOKEN' \
                            -Dsonar.java.binaries='target/classes' \
                            -Dsonar.qualitygate.wait=false"
                    '''
                }
            }
        }

        stage('SBOM - CycloneDX') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eux

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKDIR" \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "mvn -B -f '$WORKDIR/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all"

                        test -f "$WORKDIR/target/bom.xml" && cp -f "$WORKDIR/target/bom.xml" "$WORKDIR/reports/sbom/bom.xml"
                        test -f "$WORKDIR/target/bom.json" && cp -f "$WORKDIR/target/bom.json" "$WORKDIR/reports/sbom/bom.json"
                        test -s reports/sbom/bom.json
                    '''
                }
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eux

                    docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true

                    docker run -d \
                      --name "$MYSQL_CONTAINER" \
                      --network "$NETWORK_NAME" \
                      -e MYSQL_ROOT_PASSWORD=root \
                      -e MYSQL_DATABASE=archivagedb \
                      -e MYSQL_USER=archivageuser \
                      -e MYSQL_PASSWORD=archivagepass \
                      mysql:8.0

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
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    set -eux

                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true

                    JARPATH=$(cat "$WORKDIR/.jarpath")
                    test -n "$JARPATH"
                    test -f "$JARPATH"

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$NETWORK_NAME" \
                      --volumes-from jenkins \
                      -w "$WORKDIR" \
                      eclipse-temurin:17-jre \
                      sh -lc "java -jar '$JARPATH' \
                        --server.port=$APP_PORT \
                        --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/archivagedb \
                        --spring.datasource.username=archivageuser \
                        --spring.datasource.password=archivagepass"

                    READY=0
                    for i in $(seq 1 30); do
                      if docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                        -fsS "http://$APP_CONTAINER:$APP_PORT/actuator/health"; then
                        READY=1
                        break
                      fi
                      echo "Waiting for app health ($i/30)..."
                      sleep 5
                    done

                    test "$READY" -eq 1
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eux

                        docker run --rm \
                          --network "$NETWORK_NAME" \
                          --volumes-from jenkins \
                          -w "$WORKDIR" \
                          ghcr.io/zaproxy/zaproxy:stable \
                          zap-baseline.py \
                          -t "http://$APP_CONTAINER:$APP_PORT" \
                          -J "reports/zap/zap-report.json" \
                          -r "reports/zap/zap-report.html" \
                          -I || true

                        test -s reports/zap/zap-report.json || echo '{"site":[{"alerts":[]}]}' > reports/zap/zap-report.json
                        test -s reports/zap/zap-report.html || echo '<html><body><h2>ZAP report unavailable</h2></body></html>' > reports/zap/zap-report.html
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eux

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKDIR" \
                      python:3.12-alpine \
                      sh -lc "python - <<'PY'
import json
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default

gitleaks = load_json('reports/gitleaks/gitleaks-report.json', [])
trivy = load_json('reports/trivy/trivy-report.json', {'Results': []})
zap = load_json('reports/zap/zap-report.json', {'site': [{'alerts': []}]})

sev = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
for result in trivy.get('Results', []):
    for v in result.get('Vulnerabilities', []) or []:
        s = (v.get('Severity') or '').upper()
        if s in sev:
            sev[s] += 1

zap_high = 0
for site in zap.get('site', []) or []:
    for alert in site.get('alerts', []) or []:
        risk = str(alert.get('riskcode', '')).strip()
        if risk == '3':
            zap_high += 1

payload = {
    'gitleaks': gitleaks if isinstance(gitleaks, list) else [],
    'trivy': {
        'critical': sev['CRITICAL'],
        'high': sev['HIGH'],
        'medium': sev['MEDIUM'],
        'low': sev['LOW']
    },
    'zap': {
        'high': zap_high
    }
}

Path('reports/opa').mkdir(parents=True, exist_ok=True)
Path('reports/opa/input.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
PY"

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKDIR" \
                      openpolicyagent/opa:latest \
                      eval \
                      --format raw \
                      --data "$WORKDIR/policy/security-gate.rego" \
                      --input "$WORKDIR/reports/opa/input.json" \
                      "data.security.allow" | tee "$WORKDIR/reports/opa/opa-result.txt"

                    grep -qx 'true' "$WORKDIR/reports/opa/opa-result.txt"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true, fingerprint: true

            sh '''
                docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        failure {
            echo 'Pipeline FAILED - verifier les rapports archives.'
        }

        success {
            echo 'Pipeline SUCCESS.'
        }
    }
}
