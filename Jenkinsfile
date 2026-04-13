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

        SONAR_HOST_URL   = 'http://host.docker.internal:9000'
        SONAR_PROJECT_KEY= 'archivage-Doc'

        MAVEN_IMAGE      = 'maven:3.9.9-eclipse-temurin-17'
        JRE_IMAGE        = 'eclipse-temurin:17-jre'
        GITLEAKS_IMAGE   = 'zricethezav/gitleaks:latest'
        TRIVY_IMAGE      = 'ghcr.io/aquasecurity/trivy:latest'
        ZAP_IMAGE        = 'ghcr.io/zaproxy/zaproxy:stable'
        OPA_IMAGE        = 'openpolicyagent/opa:latest'
        PYTHON_IMAGE     = 'python:3.12-alpine'
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
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa policy .trivycache
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
                      sh -lc "
                        mvn -B \
                          -f '$WORKSPACE/pom.xml' \
                          -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                          clean package -DskipTests
                      "

                    ls -1 "$WORKSPACE"/target/*.jar | grep -v '\\.original$' >/dev/null
                '''
            }
        }

        stage('Secrets - Gitleaks') {
            steps {
                sh '''
                    set +e
                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      "$GITLEAKS_IMAGE" \
                      detect \
                      --source . \
                      --log-opts="--all" \
                      --report-format json \
                      --report-path reports/gitleaks/gitleaks-report.json \
                      --exit-code 0
                    RC=$?
                    test -s reports/gitleaks/gitleaks-report.json || echo '[]' > reports/gitleaks/gitleaks-report.json
                    exit 0
                '''
            }
        }

        stage('SCA - Trivy FS') {
            steps {
                sh '''
                    set +e

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                      "$TRIVY_IMAGE" fs \
                      --scanners vuln \
                      --severity LOW,MEDIUM,HIGH,CRITICAL \
                      --format json \
                      --output reports/trivy/trivy-report.json \
                      .

                    test -s reports/trivy/trivy-report.json || echo '{"Results":[]}' > reports/trivy/trivy-report.json

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                      "$TRIVY_IMAGE" fs \
                      --scanners vuln \
                      --severity LOW,MEDIUM,HIGH,CRITICAL \
                      --format template \
                      --template "@contrib/html.tpl" \
                      --output reports/trivy/trivy-report.html \
                      .

                    test -s reports/trivy/trivy-report.html || cat > reports/trivy/trivy-report.html <<'HTML'
                    <html><body><h2>Trivy report unavailable</h2></body></html>
HTML
                    exit 0
                '''
            }
        }

        stage('SAST - SonarQube') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        set +e
                        docker run --rm \
                          --volumes-from jenkins \
                          --add-host=host.docker.internal:host-gateway \
                          -w "$WORKSPACE" \
                          "$MAVEN_IMAGE" \
                          sh -lc "
                            mvn -B \
                              -f '$WORKSPACE/pom.xml' \
                              -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                              clean compile \
                              org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                              -DskipTests \
                              -Dsonar.projectKey='$SONAR_PROJECT_KEY' \
                              -Dsonar.host.url='$SONAR_HOST_URL' \
                              -Dsonar.token='$SONAR_TOKEN' \
                              -Dsonar.java.binaries=target/classes \
                              -Dsonar.qualitygate.wait=false
                          "
                        exit 0
                    '''
                }
            }
        }

        stage('SBOM - CycloneDX') {
            steps {
                sh '''
                    set +e
                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      "$MAVEN_IMAGE" \
                      sh -lc "
                        mvn -B \
                          -f '$WORKSPACE/pom.xml' \
                          -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                          org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                          -DoutputFormat=all
                      "

                    test -f "$WORKSPACE/target/bom.xml"  && cp -f "$WORKSPACE/target/bom.xml"  "$WORKSPACE/reports/sbom/bom.xml"
                    test -f "$WORKSPACE/target/bom.json" && cp -f "$WORKSPACE/target/bom.json" "$WORKSPACE/reports/sbom/bom.json"
                    test -s reports/sbom/bom.json || echo '{"components":[]}' > reports/sbom/bom.json
                    exit 0
                '''
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
                      mysql:8.0

                    READY=0
                    for i in $(seq 1 30); do
                      if docker run --rm \
                        --network "$DOCKER_NETWORK" \
                        mysql:8.0 \
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

                    JAR_PATH=$(ls -1 "$WORKSPACE"/target/*.jar | grep -v '\\.original$' | head -n 1)
                    test -n "$JAR_PATH"

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      -p "$APP_PORT:$APP_PORT" \
                      "$JRE_IMAGE" \
                      sh -lc "java -jar '$JAR_PATH' \
                        --server.port=$APP_PORT \
                        --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE \
                        --spring.datasource.username=$MYSQL_USER \
                        --spring.datasource.password=$MYSQL_PASS"

                    READY=0
                    for i in $(seq 1 18); do
                      STATUS=$(docker run --rm \
                        --network "$DOCKER_NETWORK" \
                        curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" \
                        "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)

                      if echo "$STATUS" | grep -q '^200$'; then
                        READY=1
                        break
                      fi

                      STATUS=$(docker run --rm \
                        --network "$DOCKER_NETWORK" \
                        curlimages/curl:8.7.1 \
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
                      echo "App did 
