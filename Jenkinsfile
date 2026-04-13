pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    environment {
        APP_PORT           = '8081'
        MYSQL_DATABASE     = 'archivage_db'
        DOCKER_NETWORK     = 'archivage-net'
        MYSQL_CONTAINER    = 'mysql-archivage'
        APP_CONTAINER      = 'app-archivage'
        APP_IMAGE          = "archivage-app:${BUILD_NUMBER}"
        MAVEN_CACHE_VOLUME = 'maven_repo_cache'
        TRIVY_CACHE_VOLUME = 'trivy_cache'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    echo "--------------------------------------------------------"
                    echo " CHECKOUT OK"
                    echo "--------------------------------------------------------"
                    pwd
                    ls -la
                    test -f pom.xml
                '''
            }
        }

        stage('Tests Unitaires') {
            steps {
                sh '''#!/bin/sh
                    set -eu

                    echo "--------------------------------------------------------"
                    echo " [1/7] TESTS UNITAIRES (JUnit + JaCoCo)"
                    echo "--------------------------------------------------------"

                    CID=$(docker create \
                      -w /workspace \
                      -v "${MAVEN_CACHE_VOLUME}:/root/.m2" \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -q -B verify -Dmaven.repo.local=/root/.m2/repository)

                    cleanup() {
                      docker rm -f "$CID" >/dev/null 2>&1 || true
                    }
                    trap cleanup EXIT

                    docker cp "${WORKSPACE}/." "${CID}:/workspace"
                    docker start -a "$CID"
                    docker cp "${CID}:/workspace/target" "${WORKSPACE}/" || true
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml'
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'target/site/jacoco',
                        reportFiles: 'index.html',
                        reportName: 'JaCoCo Coverage'
                    ])
                }
            }
        }

        stage('Build & Package') {
            steps {
                sh '''#!/bin/sh
                    set -eu

                    echo "--------------------------------------------------------"
                    echo " [2/7] COMPILATION (Maven package)"
                    echo "--------------------------------------------------------"

                    CID=$(docker create \
                      -w /workspace \
                      -v "${MAVEN_CACHE_VOLUME}:/root/.m2" \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -q -B -T 1C package -DskipTests -Dmaven.repo.local=/root/.m2/repository)

                    cleanup() {
                      docker rm -f "$CID" >/dev/null 2>&1 || true
                    }
                    trap cleanup EXIT

                    docker cp "${WORKSPACE}/." "${CID}:/workspace"
                    docker start -a "$CID"
                    docker cp "${CID}:/workspace/target" "${WORKSPACE}/" || true
                '''
            }
        }

        stage('Analyses Statiques (SAST/SCA)') {
            parallel {

                stage('Secrets (Gitleaks)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/sh
                                set -eu

                                echo " [3A] SCAN DES SECRETS (Gitleaks)"
                                mkdir -p "${WORKSPACE}/reports/gitleaks"

                                CID=$(docker create \
                                  --security-opt no-new-privileges \
                                  zricethezav/gitleaks:latest detect \
                                    --source /workspace \
                                    --log-opts="--all" \
                                    --report-format json \
                                    --report-path /workspace/reports/gitleaks/gitleaks-report.json \
                                    --exit-code 0)

                                cleanup() {
                                  docker rm -f "$CID" >/dev/null 2>&1 || true
                                }
                                trap cleanup EXIT

                                docker cp "${WORKSPACE}/." "${CID}:/workspace"
                                docker start -a "$CID"
                                docker cp "${CID}:/workspace/reports/gitleaks/." "${WORKSPACE}/reports/gitleaks/" || true
                            '''
                        }
                    }
                }

                stage('SCA (Trivy FS)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/sh
                                set -eu

                                echo " [3B] SCAN DES DEPENDANCES (Trivy FS)"
                                mkdir -p "${WORKSPACE}/reports/trivy"

                                CID=$(docker create \
                                  --security-opt no-new-privileges \
                                  -v "${TRIVY_CACHE_VOLUME}:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs \
                                    --scanners vuln,secret \
                                    --severity LOW,MEDIUM,HIGH,CRITICAL \
                                    --format json \
                                    --output /workspace/reports/trivy/trivy-fs-report.json \
                                    /workspace)

                                cleanup() {
                                  docker rm -f "$CID" >/dev/null 2>&1 || true
                                }
                                trap cleanup EXIT

                                docker cp "${WORKSPACE}/." "${CID}:/workspace"
                                docker start -a "$CID"
                                docker cp "${CID}:/workspace/reports/trivy/." "${WORKSPACE}/reports/trivy/" || true
                            '''
                        }
                    }
                }

                stage('SAST (SonarQube)') {
                    steps {
                        withSonarQubeEnv('SonarQube') {
                            withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                                sh '''#!/bin/sh
                                    set -eu

                                    echo " [3C] ANALYSE QUALITE (SonarQube)"

                                    CID=$(docker create \
                                      --add-host=host.docker.internal:host-gateway \
                                      -w /workspace \
                                      -v "${MAVEN_CACHE_VOLUME}:/root/.m2" \
                                      maven:3.9.9-eclipse-temurin-17 \
                                      mvn -q -B \
                                        -Dmaven.repo.local=/root/.m2/repository \
                                        org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                        -Dsonar.projectKey=archivage-Doc \
                                        -Dsonar.host.url="${SONAR_HOST_URL}" \
                                        -Dsonar.login="${SONAR_TOKEN}" \
                                        -Dsonar.java.binaries=target/classes)

                                    cleanup() {
                                      docker rm -f "$CID" >/dev/null 2>&1 || true
                                    }
                                    trap cleanup EXIT

                                    docker cp "${WORKSPACE}/." "${CID}:/workspace"
                                    docker start -a "$CID"
                                    docker cp "${CID}:/workspace/target" "${WORKSPACE}/" || true
                                '''
                            }
                        }
                    }
                }

                stage('SBOM (CycloneDX / Syft)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/sh
                                set -eu

                                echo " [3D] GENERATION SBOM (Syft)"
                                mkdir -p "${WORKSPACE}/reports/sbom"

                                CID=$(docker create \
                                  --security-opt no-new-privileges \
                                  anchore/syft:latest \
                                  /workspace \
                                  -o cyclonedx-json \
                                  --file /workspace/reports/sbom/sbom-cyclonedx.json)

                                cleanup() {
                                  docker rm -f "$CID" >/dev/null 2>&1 || true
                                }
                                trap cleanup EXIT

                                docker cp "${WORKSPACE}/." "${CID}:/workspace"
                                docker start -a "$CID"
                                docker cp "${CID}:/workspace/reports/sbom/." "${WORKSPACE}/reports/sbom/" || true
                            '''
                        }
                    }
                }
            }
        }

        stage('SonarQube Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build Image Docker') {
            steps {
                sh '''#!/bin/sh
                    set -eu

                    echo "--------------------------------------------------------"
                    echo " [4/7] BUILD IMAGE DOCKER"
                    echo "--------------------------------------------------------"

                    docker build -t "${APP_IMAGE}" "${WORKSPACE}"
                    echo "Image construite : ${APP_IMAGE}"
                '''
            }
        }

        stage('Trivy Image Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''#!/bin/sh
                        set -eu

                        echo " [5/7] SCAN IMAGE DOCKER (Trivy)"
                        mkdir -p "${WORKSPACE}/reports/trivy"

                        CID=$(docker create \
                          --security-opt no-new-privileges \
                          -v /var/run/docker.sock:/var/run/docker.sock \
                          -v "${TRIVY_CACHE_VOLUME}:/root/.cache/trivy" \
                          ghcr.io/aquasecurity/trivy:latest image \
                            --severity HIGH,CRITICAL \
                            --format json \
                            --output /tmp/trivy-image-report.json \
                            "${APP_IMAGE}")

                        cleanup() {
                          docker rm -f "$CID" >/dev/null 2>&1 || true
                        }
                        trap cleanup EXIT

                        docker start -a "$CID"
                        docker cp "${CID}:/tmp/trivy-image-report.json" "${WORKSPACE}/reports/trivy/trivy-image-report.json" || true
                    '''
                }
            }
        }

        stage('Deploy (Test Env)') {
            steps {
                withCredentials([
                    string(credentialsId: 'mysql-root-password', variable: 'MYSQL_ROOT_PASS'),
                    usernamePassword(
                        credentialsId: 'mysql-app-credentials',
                        usernameVariable: 'MYSQL_USER',
                        passwordVariable: 'MYSQL_PASS'
                    )
                ]) {
                    sh '''#!/bin/sh
                        set -eu

                        echo "--------------------------------------------------------"
                        echo " [6/7] DEPLOIEMENT ENVIRONNEMENT DE TEST"
                        echo "--------------------------------------------------------"

                        docker rm -f "${MYSQL_CONTAINER}" "${APP_CONTAINER}" 2>/dev/null || true
                        docker network rm "${DOCKER_NETWORK}" 2>/dev/null || true
                        docker network create "${DOCKER_NETWORK}"

                        docker run -d \
                          --name "${MYSQL_CONTAINER}" \
                          --network "${DOCKER_NETWORK}" \
                          --security-opt no-new-privileges \
                          -e MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASS}" \
                          -e MYSQL_DATABASE="${MYSQL_DATABASE}" \
                          -e MYSQL_USER="${MYSQL_USER}" \
                          -e MYSQL_PASSWORD="${MYSQL_PASS}" \
                          mysql:8.0

                        echo "Attente demarrage MySQL..."
                        OK_MYSQL=0
                        for i in $(seq 1 24); do
                          if docker exec "${MYSQL_CONTAINER}" mysqladmin ping -h localhost -u"${MYSQL_USER}" -p"${MYSQL_PASS}" --silent >/dev/null 2>&1; then
                            OK_MYSQL=1
                            break
                          fi
                          echo "  Tentative ${i}/24..."
                          sleep 5
                        done

                        if [ "${OK_MYSQL}" -ne 1 ]; then
                          echo "MySQL n'a pas demarre correctement"
                          docker logs "${MYSQL_CONTAINER}" || true
                          exit 1
                        fi

                        docker run -d \
                          --name "${APP_CONTAINER}" \
                          --network "${DOCKER_NETWORK}" \
                          --security-opt no-new-privileges \
                          -p "${APP_PORT}:8080" \
                          -v /tmp/archivage-uploads:/app/uploads \
                          -e SPRING_PROFILES_ACTIVE=docker \
                          -e SPRING_DATASOURCE_URL="jdbc:mysql://${MYSQL_CONTAINER}:3306/${MYSQL_DATABASE}?serverTimezone=UTC" \
                          -e SPRING_DATASOURCE_USERNAME="${MYSQL_USER}" \
                          -e SPRING_DATASOURCE_PASSWORD="${MYSQL_PASS}" \
                          -e JWT_SECRET=***REMOVED*** \
                          "${APP_IMAGE}"

                        echo "Attente demarrage Spring Boot..."
                        READY=0
                        for i in $(seq 1 24); do
                          STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${APP_PORT}/actuator/health" 2>/dev/null || echo "000")
                          if echo "${STATUS}" | grep -qE "^(200|302|401|403)$"; then
                            echo "Application disponible (HTTP ${STATUS})"
                            READY=1
                            break
                          fi
                          echo "  Tentative ${i}/24 - HTTP ${STATUS}"
                          sleep 5
                        done

                        if [ "${READY}" -ne 1 ]; then
                          echo "Timeout - logs application :"
                          docker logs "${APP_CONTAINER}" 2>&1 || true
                          exit 1
                        fi
                    '''
                }
            }
        }

        stage('DAST & Policy') {
            parallel {

                stage('DAST (OWASP ZAP)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/sh
                                set -eu

                                echo " [7A] DAST - OWASP ZAP Baseline Scan"
                                mkdir -p "${WORKSPACE}/reports/zap"

                                CID=$(docker create \
                                  --security-opt no-new-privileges \
                                  --network "${DOCKER_NETWORK}" \
                                  ghcr.io/zaproxy/zaproxy:stable \
                                  zap-baseline.py \
                                    -t "http://${APP_CONTAINER}:8080" \
                                    -m 3 \
                                    -r /zap/wrk/zap-report.html \
                                    -J /zap/wrk/zap-report.json \
                                    -I)

                                cleanup() {
                                  docker rm -f "$CID" >/dev/null 2>&1 || true
                                }
                                trap cleanup EXIT

                                docker start -a "$CID"
                                docker cp "${CID}:/zap/wrk/." "${WORKSPACE}/reports/zap/" || true
                            '''
                        }
                    }
                    post {
                        always {
                            publishHTML(target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'reports/zap',
                                reportFiles: 'zap-report.html',
                                reportName: 'ZAP DAST Report'
                            ])
                        }
                    }
                }

                stage('Policy (OPA)') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh '''#!/bin/sh
                                set -eu

                                echo " [7B] POLICY CHECK (OPA)"
                                mkdir -p "${WORKSPACE}/reports/opa"

                                if [ ! -f "${WORKSPACE}/policy/security.rego" ]; then
                                  echo "ERREUR : policy/security.rego introuvable"
                                  exit 1
                                fi

                                if [ ! -f "${WORKSPACE}/reports/trivy/trivy-fs-report.json" ]; then
                                  echo "Rapport Trivy absent - OPA ignore"
                                  exit 0
                                fi

                                CID=$(docker create \
                                  --security-opt no-new-privileges \
                                  openpolicyagent/opa:latest \
                                  eval \
                                    --data /policy/security.rego \
                                    --input /data/trivy-fs-report.json \
                                    "data.security.allow" \
                                    --format raw)

                                cleanup() {
                                  docker rm -f "$CID" >/dev/null 2>&1 || true
                                }
                                trap cleanup EXIT

                                docker cp "${WORKSPACE}/policy/security.rego" "${CID}:/policy/security.rego"
                                docker cp "${WORKSPACE}/reports/trivy/trivy-fs-report.json" "${CID}:/data/trivy-fs-report.json"

                                OPA_RESULT=$(docker start -a "$CID" | tr -d '\\r' | tail -n 1)

                                echo "Resultat OPA : ${OPA_RESULT}"
                                echo "${OPA_RESULT}" > "${WORKSPACE}/reports/opa/opa-result.txt"

                                if [ "${OPA_RESULT}" != "true" ]; then
                                  echo "POLICY VIOLATION : allow=false"
                                  exit 1
                                fi

                                echo "Policy validee (allow=true)"
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            sh '''#!/bin/sh
                echo "--------------------------------------------------------"
                echo " NETTOYAGE"
                echo "--------------------------------------------------------"
                docker rm -f "${APP_CONTAINER}" "${MYSQL_CONTAINER}" 2>/dev/null || true
                docker network rm "${DOCKER_NETWORK}" 2>/dev/null || true
                docker rmi "${APP_IMAGE}" 2>/dev/null || true
            '''
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
        success {
            echo 'PIPELINE DEVSECOPS TERMINE AVEC SUCCES'
        }
        failure {
            echo 'PIPELINE ECHOUE - consultez les rapports'
        }
        unstable {
            echo 'PIPELINE INSTABLE - verifiez les stages UNSTABLE'
        }
    }
}
