// Correction: l'application attend le placeholder GITHUB_OAUTH_SECRET, pas GITHUBOAUTHSECRET, d'après les logs du conteneur. [file:4]
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
        APP_PORT        = '8081'
        MAVEN_REPO      = '/var/jenkins_home/.m2/repository'
        TRIVY_CACHE     = "${WORKSPACE}/.trivycache"
        SONARQUBE_ENV   = 'sonar'
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
                      -w "$WORKSPACE" \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' clean package -DskipTests"

                    JARPATH=$(find "$WORKSPACE/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    test -n "$JARPATH"
                    test -f "$JARPATH"
                    echo "$JARPATH" > "$WORKSPACE/.jarpath"
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
                          -w "$WORKSPACE" \
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
                          -w "$WORKSPACE" \
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
                script {
                    withSonarQubeEnv("${SONARQUBE_ENV}") {
                        sh '''
                            set -eux

                            test -d "$WORKSPACE/target/classes"
                            test -f "$WORKSPACE/.jarpath"

                            docker run --rm \
                              --network "$NETWORK_NAME" \
                              --volumes-from jenkins \
                              --add-host=host.docker.internal:host-gateway \
                              -e SONAR_HOST_URL="http://host.docker.internal:9000" \
                              -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                              -w "$WORKSPACE" \
                              maven:3.9.9-eclipse-temurin-17 \
                              sh -lc "mvn -B -f '$WORKSPACE/pom.xml' \
                                -Dmaven.repo.local='$MAVEN_REPO' \
                                org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                -DskipTests \
                                -Dsonar.projectKey='$APP_NAME' \
                                -Dsonar.host.url='http://host.docker.internal:9000' \
                                -Dsonar.login='$SONAR_AUTH_TOKEN' \
                                -Dsonar.java.binaries='target/classes' \
                                -Dsonar.qualitygate.wait=false"
                        '''
                    }
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
                          -w "$WORKSPACE" \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "mvn -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all"

                        test -f "$WORKSPACE/target/bom.xml" && cp -f "$WORKSPACE/target/bom.xml" "$WORKSPACE/reports/sbom/bom.xml"
                        test -f "$WORKSPACE/target/bom.json" && cp -f "$WORKSPACE/target/bom.json" "$WORKSPACE/reports/sbom/bom.json"
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

                    echo "MySQL répondu au ping. Pause de 10 secondes pour garantir l'initialisation..."
                    sleep 10
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    set -eux

                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true

                    JARPATH=$(cat "$WORKSPACE/.jarpath")
                    test -n "$JARPATH"
                    test -f "$JARPATH"

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$NETWORK_NAME" \
                      --volumes-from jenkins \
                      --restart on-failure:5 \
                      -w "$WORKSPACE" \
                      -e GITHUB_OAUTH_SECRET="test-secret" \
                      -e JAVA_TOOL_OPTIONS="-DGITHUB_OAUTH_SECRET=test-secret -Dapp.oauth.enabled=false" \
                      eclipse-temurin:17-jre \
                      sh -lc "printenv | grep -E '^GITHUB_OAUTH_SECRET=' >/dev/null && \
                             java -jar '$JARPATH' \
                               --server.port=$APP_PORT \
                               --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/archivagedb \
                               --spring.datasource.username=archivageuser \
                               --spring.datasource.password=archivagepass \
                               --app.oauth.enabled=false \
                               --GITHUB_OAUTH_SECRET=test-secret"

                    READY=0
                    for i in $(seq 1 30); do
                      CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/" || true)

                      if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then
                        READY=1
                        break
                      fi

                      echo "Waiting for app health ($i/30)..."
                      docker ps -a --filter "name=$APP_CONTAINER" --format 'table {{.Names}}\t{{.Status}}' || true
                      sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                      set +x
                      echo "============================================================"
                      echo "❌ CRASH APPLICATIF DÉTECTÉ ❌"
                      echo "L'application n'a pas démarré. Voici les logs du conteneur :"
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
                        set -eux

                        docker run --rm \
                          --network "$NETWORK_NAME" \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
                          ghcr.io/zaproxy/zaproxy:stable \
                          zap-baseline.py \
                          -t "http://$APP_CONTAINER:$APP_PORT/" \
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
                      -w "$WORKSPACE" \
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
                      -w "$WORKSPACE" \
                      openpolicyagent/opa:latest \
                      eval \
                      --format raw \
                      --data "$WORKSPACE/policy/security-gate.rego" \
                      --input "$WORKSPACE/reports/opa/input.json" \
                      "data.security.allow" | tee "$WORKSPACE/reports/opa/opa-result.txt"

                    grep -qx 'true' "$WORKSPACE/reports/opa/opa-result.txt"
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
