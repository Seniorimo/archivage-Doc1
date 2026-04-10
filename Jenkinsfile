pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
    }

    environment {
        APP_PORT        = '8081'
        MYSQL_ROOT_PASS = 'root'
        MYSQL_DATABASE  = 'archivage_db'
        MYSQL_USER      = 'archivage_user'
        MYSQL_PASS      = 'archivage_pass'
        DOCKER_NETWORK  = 'archivage-net'
        MYSQL_CONTAINER = 'mysql-archivage'
        APP_CONTAINER   = 'app-archivage'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Secrets - Gitleaks') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/gitleaks

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
                          zricethezav/gitleaks:latest \
                          detect \
                          --source . \
                          --log-opts="--all" \
                          --report-format json \
                          --report-path reports/gitleaks/gitleaks-report.json \
                          --exit-code 0 || true
                    '''
                }
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    docker run --rm \
                      --volumes-from jenkins \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B \
                        -f "$WORKSPACE/pom.xml" \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        clean package -DskipTests
                '''
            }
        }

        stage('SCA - Trivy') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/trivy
                        mkdir -p .trivycache

                        docker run --rm \
                          --volumes-from jenkins \
                          -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                          -v "$WORKSPACE/reports/trivy:/report" \
                          ghcr.io/aquasecurity/trivy:latest fs \
                          --scanners vuln \
                          --severity LOW,MEDIUM,HIGH,CRITICAL \
                          --format json \
                          --output /report/trivy-report.json \
                          "$WORKSPACE" || true
                    '''
                }
            }
        }

        stage('SAST - SonarQube') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        docker run --rm \
                          --volumes-from jenkins \
                          --add-host=host.docker.internal:host-gateway \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "
                            mvn -B \
                              -f '$WORKSPACE/pom.xml' \
                              -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                              clean compile \
                              org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                              -Dsonar.projectKey=archivage-Doc \
                              -Dsonar.host.url=http://host.docker.internal:9000 \
                              -Dsonar.login=$SONAR_TOKEN \
                              -Dsonar.java.binaries=target/classes
                          "
                    '''
                }
            }
        }

        stage('SBOM - CycloneDX') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/sbom

                        docker run --rm \
                          --volumes-from jenkins \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "
                            mvn -B \
                              -f '$WORKSPACE/pom.xml' \
                              -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                              org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                              -DoutputFormat=all &&
                            cp -f '$WORKSPACE/target/bom.xml' '$WORKSPACE/reports/sbom/bom.xml' &&
                            cp -f '$WORKSPACE/target/bom.json' '$WORKSPACE/reports/sbom/bom.json'
                          " || true
                    '''
                }
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    docker rm -f "$MYSQL_CONTAINER" 2>/dev/null || true
                    docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK"

                    docker run -d \
                      --name "$MYSQL_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASS" \
                      -e MYSQL_DATABASE="$MYSQL_DATABASE" \
                      -e MYSQL_USER="$MYSQL_USER" \
                      -e MYSQL_PASSWORD="$MYSQL_PASS" \
                      mysql:8.0

                    sleep 25
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    docker rm -f "$APP_CONTAINER" 2>/dev/null || true

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      --volumes-from jenkins \
                      --add-host=host.docker.internal:host-gateway \
                      -p "$APP_PORT:$APP_PORT" \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B \
                        -f '$WORKSPACE/pom.xml' \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        spring-boot:run \
                        -Dspring-boot.run.arguments='--server.port=$APP_PORT --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS'"

                    READY=0
                    for i in $(seq 1 12); do
                      STATUS=$(docker run --rm \
                        --network "$DOCKER_NETWORK" \
                        curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" \
                        "http://$APP_CONTAINER:$APP_PORT/" || true)

                      echo "Attempt $i/12 -> HTTP status: $STATUS"

                      if echo "$STATUS" | grep -qE "200|302|401|403"; then
                        READY=1
                        break
                      fi

                      sleep 10
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
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/zap

                        docker run --rm \
                          --user root \
                          --add-host=host.docker.internal:host-gateway \
                          --volumes-from jenkins \
                          -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                          ghcr.io/zaproxy/zaproxy:stable \
                          zap-baseline.py \
                          -t "http://host.docker.internal:$APP_PORT" \
                          -r zap-report.html \
                          -J zap-report.json \
                          -I || true
                    '''
                }
            }
        }

        stage('Policy - OPA') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/opa
                        mkdir -p policy

                        cat > policy/security.rego <<'EOF'
package security

default allow = false

trivy_high_count := count([v |
  some i
  input.trivy.Results[i].Vulnerabilities[_].Severity == "HIGH"
  v := 1
])

trivy_critical_count := count([v |
  some i
  input.trivy.Results[i].Vulnerabilities[_].Severity == "CRITICAL"
  v := 1
])

zap_high_count := count([v |
  some s
  input.zap.site[s].alerts[_].riskcode == "3"
  v := 1
])

allow if {
  trivy_critical_count == 0
  zap_high_count == 0
}
EOF

                        cat > reports/opa/input.json <<EOF
{
  "trivy": $(cat reports/trivy/trivy-report.json 2>/dev/null || echo '{}'),
  "zap": $(cat reports/zap/zap-report.json 2>/dev/null || echo '{}')
}
EOF

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
                          openpolicyagent/opa:latest \
                          eval \
                          --format pretty \
                          --data policy/security.rego \
                          --input reports/opa/input.json \
                          "data.security" > reports/opa/opa-result.txt || true
                    '''
                }
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
            echo '✅ Pipeline DevSecOps termine avec succes'
        }

        unstable {
            echo '⚠️ Pipeline termine, mais certains controles ont remonte des alertes non bloquantes'
        }

        failure {
            echo '❌ Pipeline echoue — verifier les logs'
        }
    }
}
