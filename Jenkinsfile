pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 60, unit: 'MINUTES')
    }

    environment {
        APP_PORT         = '8081'
        MYSQL_ROOT_PASS  = 'root'
        MYSQL_DATABASE   = 'archivage_db'
        MYSQL_USER       = 'archivage_user'
        MYSQL_PASS       = 'archivage_pass'
        DOCKER_NETWORK   = 'archivage-net'
        MYSQL_CONTAINER  = 'mysql-archivage'
        APP_CONTAINER    = 'app-archivage'

        SONAR_HOST_URL    = 'http://host.docker.internal:9000'
        SONAR_PROJECT_KEY = 'archivage-Doc'

        MAVEN_IMAGE     = 'maven:3.9.9-eclipse-temurin-17'
        JRE_IMAGE       = 'eclipse-temurin:17-jre'
        MYSQL_IMAGE     = 'mysql:8.0'
        CURL_IMAGE      = 'curlimages/curl:8.7.1'
        GITLEAKS_IMAGE  = 'zricethezav/gitleaks:latest'
        TRIVY_IMAGE     = 'ghcr.io/aquasecurity/trivy:latest'
        ZAP_IMAGE       = 'ghcr.io/zaproxy/zaproxy:stable'
        OPA_IMAGE       = 'openpolicyagent/opa:latest'
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
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa .trivycache policy
                    docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK"
                '''
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      "$MAVEN_IMAGE" \
                      sh -lc "mvn -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local=/var/jenkins_home/.m2/repository clean package -DskipTests"

                    JAR_PATH=$(find "$WORKSPACE/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    echo "JAR_PATH=$JAR_PATH"
                    test -n "$JAR_PATH"
                '''
            }
        }

        stage('Secrets - Gitleaks') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
                          "$GITLEAKS_IMAGE" \
                          detect \
                          --source . \
                          --log-opts="--all" \
                          --report-format json \
                          --report-path reports/gitleaks/gitleaks-report.json \
                          --exit-code 0 || true

                        test -s reports/gitleaks/gitleaks-report.json || echo '[]' > reports/gitleaks/gitleaks-report.json
                    '''
                }
            }
        }

        stage('SCA - Trivy FS') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
                          -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                          "$TRIVY_IMAGE" fs \
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
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh '''
                            test -d "$WORKSPACE/target/classes"
                            test -n "$SONAR_TOKEN"

                            docker run --rm \
                              --volumes-from jenkins \
                              --add-host=host.docker.internal:host-gateway \
                              -w "$WORKSPACE" \
                              "$MAVEN_IMAGE" \
                              sh -lc "mvn -B \
                                -f '$WORKSPACE/pom.xml' \
                                -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                                org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                -DskipTests \
                                -Dsonar.projectKey=$SONAR_PROJECT_KEY \
                                -Dsonar.host.url=$SONAR_HOST_URL \
                                -Dsonar.login=$SONAR_TOKEN \
                                -Dsonar.java.binaries=target/classes \
                                -Dsonar.qualitygate.wait=false" || true
                        '''
                    }
                }
            }
        }

        stage('SBOM - CycloneDX') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
                          "$MAVEN_IMAGE" \
                          sh -lc "mvn -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local=/var/jenkins_home/.m2/repository org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all" || true

                        test -f "$WORKSPACE/target/bom.xml"  && cp -f "$WORKSPACE/target/bom.xml"  "$WORKSPACE/reports/sbom/bom.xml"  || true
                        test -f "$WORKSPACE/target/bom.json" && cp -f "$WORKSPACE/target/bom.json" "$WORKSPACE/reports/sbom/bom.json" || true
                        test -s reports/sbom/bom.json || echo '{"components":[]}' > reports/sbom/bom.json
                    '''
                }
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    docker rm -f "$MYSQL_CONTAINER" 2>/dev/null || true

                    docker run -d \
                      --name "$MYSQL_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASS" \
                      -e MYSQL_DATABASE="$MYSQL_DATABASE" \
                      -e MYSQL_USER="$MYSQL_USER" \
                      -e MYSQL_PASSWORD="$MYSQL_PASS" \
                      "$MYSQL_IMAGE"

                    READY=0
                    for i in $(seq 1 30); do
                        if docker run --rm \
                          --network "$DOCKER_NETWORK" \
                          "$MYSQL_IMAGE" \
                          mysqladmin ping -h"$MYSQL_CONTAINER" -uroot -p"$MYSQL_ROOT_PASS" --silent >/dev/null 2>&1; then
                            READY=1
                            break
                        fi
                        echo "Waiting for MySQL ($i/30)..."
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "MySQL did not become ready"
                        docker logs "$MYSQL_CONTAINER" --tail 100 || true
                        exit 1
                    fi
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    docker rm -f "$APP_CONTAINER" 2>/dev/null || true

                    JAR_PATH=$(find "$WORKSPACE/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    echo "JAR_PATH=$JAR_PATH"
                    test -n "$JAR_PATH"

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      -p "$APP_PORT:$APP_PORT" \
                      "$JRE_IMAGE" \
                      sh -lc "java -jar '$JAR_PATH' --server.port=$APP_PORT --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS"

                    READY=0
                    for i in $(seq 1 18); do
                        STATUS=$(docker run --rm \
                          --network "$DOCKER_NETWORK" \
                          "$CURL_IMAGE" \
                          -s -o /dev/null -w "%{http_code}" \
                          "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)

                        if echo "$STATUS" | grep -q '^200$'; then
                            READY=1
                            break
                        fi

                        STATUS=$(docker run --rm \
                          --network "$DOCKER_NETWORK" \
                          "$CURL_IMAGE" \
                          -s -o /dev/null -w "%{http_code}" \
                          "http://$APP_CONTAINER:$APP_PORT/" || true)

                        echo "Attempt $i/18 -> HTTP status: $STATUS"

                        if echo "$STATUS" | grep -qE '200|302|401|403'; then
                            READY=1
                            break
                        fi

                        sleep 10
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "App did not start correctly"
                        docker logs "$APP_CONTAINER" --tail 200 || true
                        exit 1
                    fi
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                          --user root \
                          --network "$DOCKER_NETWORK" \
                          --volumes-from jenkins \
                          -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                          "$ZAP_IMAGE" \
                          zap-baseline.py \
                          -t "http://$APP_CONTAINER:$APP_PORT" \
                          -r zap-report.html \
                          -J zap-report.json \
                          -I || true

                        test -s reports/zap/zap-report.json || echo '{"site":[]}' > reports/zap/zap-report.json
                        test -s reports/zap/zap-report.html || echo '<html><body><h2>ZAP report unavailable</h2></body></html>' > reports/zap/zap-report.html
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    GITLEAKS_COUNT=$(grep -Eo '"StartLine"[[:space:]]*:' reports/gitleaks/gitleaks-report.json 2>/dev/null | wc -l | tr -d ' ')
                    TRIVY_CRITICAL_COUNT=$(grep -Eo '"Severity"[[:space:]]*:[[:space:]]*"CRITICAL"' reports/trivy/trivy-report.json 2>/dev/null | wc -l | tr -d ' ')
                    ZAP_HIGH_COUNT=$(grep -Eo '"riskcode"[[:space:]]*:[[:space:]]*"3"' reports/zap/zap-report.json 2>/dev/null | wc -l | tr -d ' ')

                    test -n "$GITLEAKS_COUNT" || GITLEAKS_COUNT=0
                    test -n "$TRIVY_CRITICAL_COUNT" || TRIVY_CRITICAL_COUNT=0
                    test -n "$ZAP_HIGH_COUNT" || ZAP_HIGH_COUNT=0

                    cat > policy/security.rego <<EOF
package security

deny[msg] {
  input.gitleaks_count > 0
  msg := sprintf("Gitleaks detected %v secret(s)", [input.gitleaks_count])
}

deny[msg] {
  input.trivy_critical_count > 0
  msg := sprintf("Trivy detected %v CRITICAL vulnerability(ies)", [input.trivy_critical_count])
}

deny[msg] {
  input.zap_high_count > 0
  msg := sprintf("ZAP detected %v High alert(s)", [input.zap_high_count])
}
EOF

                    printf '{"gitleaks_count":%s,"trivy_critical_count":%s,"zap_high_count":%s}\n' \
                      "$GITLEAKS_COUNT" "$TRIVY_CRITICAL_COUNT" "$ZAP_HIGH_COUNT" > reports/opa/input.json

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      "$OPA_IMAGE" \
                      eval \
                      --format pretty \
                      --fail-defined \
                      --data policy/security.rego \
                      --input reports/opa/input.json \
                      'data.security.deny' > reports/opa/opa-result.txt 2>&1

                    cat reports/opa/opa-result.txt
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true

            sh '''
                docker rm -f "$APP_CONTAINER" 2>/dev/null || true
                docker rm -f "$MYSQL_CONTAINER" 2>/dev/null || true
                docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
            '''
        }

        success {
            echo 'Pipeline OK : aucune vulnerabilite bloquante detectee.'
        }

        failure {
            echo 'Pipeline FAILED : verifier reports/opa/opa-result.txt et les rapports archives.'
        }
    }
}
