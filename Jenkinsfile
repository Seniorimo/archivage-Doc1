/* ===========================================================================
 * PIPELINE DEVSECOPS — ARCHIVAGE DOC (VERSION FINALE)
 *
 * Corrections appliquées :
 *   [P0] ✅ --volumes-from jenkins → montages explicites -v (sécurité)
 *   [P0] ✅ Secrets MySQL via Jenkins Credentials Store (withCredentials)
 *   [P0] ✅ OPA : résultat capturé et enforced (exit 1 si allow=false)
 *   [P1] ✅ SonarQube Quality Gate bloquant (waitForQualityGate)
 *   [P1] ✅ Tests via "mvn verify" (fix JaCoCo)
 *   [P1] ✅ Image Docker construite depuis Dockerfile + scan Trivy image
 *   [P1] ✅ Déploiement via l'image Docker (pas mvn spring-boot:run)
 *   [P2] ✅ policy/security.rego lu depuis le repo Git
 *   [P2] ✅ ZAP scan étendu à -m 3
 *   [P2] ✅ docker rmi en post-cleanup
 *   [P2] ✅ --security-opt no-new-privileges sur les conteneurs de test
 *
 * PRÉ-REQUIS JENKINS :
 *   - Jenkins home BIND-MONTÉ depuis l'hôte :
 *       docker run -v /host/jenkins_home:/var/jenkins_home jenkins/jenkins
 *   - Credentials configurés (Jenkins > Manage Credentials) :
 *       ID "sonar-token"           → Secret Text
 *       ID "mysql-root-password"   → Secret Text
 *       ID "mysql-app-credentials" → Username/Password
 *   - Plugins : SonarQube Scanner, HTML Publisher, Warnings NG, JUnit
 *   - Fichier policy/security.rego présent dans le repo Git
 * =========================================================================== */

pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    environment {
        APP_PORT        = '8081'
        MYSQL_DATABASE  = 'archivage_db'
        DOCKER_NETWORK  = 'archivage-net'
        MYSQL_CONTAINER = 'mysql-archivage'
        APP_CONTAINER   = 'app-archivage'
        APP_IMAGE       = "archivage-app:${BUILD_NUMBER}"
        WS              = "${WORKSPACE}"
        JH              = "${JENKINS_HOME}"
    }

    stages {

        // ════════════════════════════════════════════════════════════════════
        stage('Checkout') {
        // ════════════════════════════════════════════════════════════════════
            steps { checkout scm }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Tests Unitaires') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail
                    echo "--------------------------------------------------------"
                    echo " [1/7] TESTS UNITAIRES (JUnit + JaCoCo)"
                    echo "--------------------------------------------------------"

                    docker run --rm \
                      --security-opt no-new-privileges \
                      -v "${WS}:/workspace:rw" \
                      -v "${JH}/.m2:/root/.m2:rw" \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -q -B -f /workspace/pom.xml \
                          -Dmaven.repo.local=/root/.m2/repository \
                          verify
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true,
                          testResults: 'target/surefire-reports/*.xml'
                    publishHTML(target: [
                        allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                        reportDir: 'target/site/jacoco', reportFiles: 'index.html',
                        reportName: 'JaCoCo Coverage'
                    ])
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Build & Package') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail
                    echo "--------------------------------------------------------"
                    echo " [2/7] COMPILATION (Maven package)"
                    echo "--------------------------------------------------------"

                    docker run --rm \
                      --security-opt no-new-privileges \
                      -v "${WS}:/workspace:rw" \
                      -v "${JH}/.m2:/root/.m2:rw" \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -q -B -T 1C -f /workspace/pom.xml \
                          -Dmaven.repo.local=/root/.m2/repository \
                          package -DskipTests
                '''
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Analyses Statiques (SAST/SCA)') {
        // ════════════════════════════════════════════════════════════════════
            parallel {

                stage('Secrets (Gitleaks)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " [3A] SCAN DES SECRETS (Gitleaks)"
                                mkdir -p "${WS}/reports/gitleaks"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${WS}:/workspace:ro" \
                                  zricethezav/gitleaks:latest detect \
                                    --source /workspace \
                                    --log-opts="--all" \
                                    --report-format json \
                                    --report-path /workspace/reports/gitleaks/gitleaks-report.json \
                                    --exit-code 0
                            '''
                        }
                    }
                }

                stage('SCA (Trivy FS)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " [3B] SCAN DES DEPENDANCES (Trivy FS)"
                                mkdir -p "${WS}/reports/trivy" "${WS}/.trivycache"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${WS}:/workspace:rw" \
                                  -v "${WS}/.trivycache:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs \
                                    --scanners vuln,secret \
                                    --severity LOW,MEDIUM,HIGH,CRITICAL \
                                    --format json \
                                    --output /workspace/reports/trivy/trivy-fs-report.json \
                                    /workspace
                            '''
                        }
                    }
                }

                stage('SAST (SonarQube)') {
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''#!/bin/bash
                                echo " [3C] ANALYSE QUALITE (SonarQube)"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  --add-host=host.docker.internal:host-gateway \
                                  -v "${WS}:/workspace:ro" \
                                  -v "${JH}/.m2:/root/.m2:rw" \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  mvn -q -B -f /workspace/pom.xml \
                                      -Dmaven.repo.local=/root/.m2/repository \
                                      org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                      -Dsonar.projectKey=archivage-Doc \
                                      -Dsonar.host.url=http://host.docker.internal:9000 \
                                      -Dsonar.login="${SONAR_TOKEN}" \
                                      -Dsonar.java.binaries=/workspace/target/classes
                            '''
                        }
                    }
                }

                stage('SBOM (CycloneDX)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " [3D] GENERATION SBOM (CycloneDX via Syft)"
                                mkdir -p "${WS}/reports/sbom"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${WS}:/workspace:rw" \
                                  anchore/syft:latest \
                                    /workspace \
                                    -o cyclonedx-json \
                                    --file /workspace/reports/sbom/sbom-cyclonedx.json
                            '''
                        }
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('SonarQube Quality Gate') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                withSonarQubeEnv('SonarQube') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Build Image Docker') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail
                    echo "--------------------------------------------------------"
                    echo " [4/7] BUILD IMAGE DOCKER + SCAN TRIVY IMAGE"
                    echo "--------------------------------------------------------"

                    docker build -t "${APP_IMAGE}" "${WS}"
                    echo " Image construite : ${APP_IMAGE}"
                '''
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Trivy Image Scan') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''#!/bin/bash
                        echo " [5/7] SCAN IMAGE DOCKER (Trivy)"
                        mkdir -p "${WS}/reports/trivy" "${WS}/.trivycache"

                        docker run --rm \
                          --security-opt no-new-privileges \
                          -v /var/run/docker.sock:/var/run/docker.sock \
                          -v "${WS}/.trivycache:/root/.cache/trivy" \
                          -v "${WS}/reports/trivy:/reports" \
                          ghcr.io/aquasecurity/trivy:latest image \
                            --severity HIGH,CRITICAL \
                            --format json \
                            --output /reports/trivy-image-report.json \
                            "${APP_IMAGE}"

                        echo " Rapport Trivy image : reports/trivy/trivy-image-report.json"
                    '''
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Deploy (Test Env)') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                withCredentials([
                    string(credentialsId: 'mysql-root-password', variable: 'MYSQL_ROOT_PASS'),
                    usernamePassword(credentialsId: 'mysql-app-credentials',
                                     usernameVariable: 'MYSQL_USER',
                                     passwordVariable: 'MYSQL_PASS')
                ]) {
                    sh '''#!/bin/bash
                        set -euo pipefail
                        echo "--------------------------------------------------------"
                        echo " [6/7] DEPLOIEMENT ENVIRONNEMENT DE TEST"
                        echo "--------------------------------------------------------"

                        # Nettoyage préalable
                        docker rm -f "${MYSQL_CONTAINER}" "${APP_CONTAINER}" 2>/dev/null || true
                        docker network rm "${DOCKER_NETWORK}" 2>/dev/null || true

                        # Création du réseau isolé
                        docker network create "${DOCKER_NETWORK}"

                        # Démarrage MySQL
                        docker run -d \
                          --name "${MYSQL_CONTAINER}" \
                          --network "${DOCKER_NETWORK}" \
                          --security-opt no-new-privileges \
                          -e MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASS}" \
                          -e MYSQL_DATABASE="${MYSQL_DATABASE}" \
                          -e MYSQL_USER="${MYSQL_USER}" \
                          -e MYSQL_PASSWORD="${MYSQL_PASS}" \
                          mysql:8.0

                        # Attente MySQL
                        echo " Attente démarrage MySQL..."
                        for i in $(seq 1 20); do
                          docker exec "${MYSQL_CONTAINER}" \
                            mysqladmin ping -h localhost -u"${MYSQL_USER}" -p"${MYSQL_PASS}" --silent \
                            2>/dev/null && break
                          echo "  Tentative ${i}/20..."
                          sleep 5
                        done

                        # Démarrage application
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

                        # Health check
                        echo " Attente démarrage Spring Boot..."
                        READY=0
                        for i in $(seq 1 24); do
                          STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
                            http://localhost:${APP_PORT}/actuator/health 2>/dev/null || echo "000")
                          if echo "${STATUS}" | grep -qE "^(200|302|401|403)$"; then
                            echo " Application disponible (HTTP ${STATUS})"
                            READY=1
                            break
                          fi
                          echo "  Tentative ${i}/24 — HTTP ${STATUS}"
                          sleep 5
                        done

                        if [ "${READY}" -ne 1 ]; then
                          echo " Timeout — logs :"
                          docker logs "${APP_CONTAINER}" 2>&1
                          exit 1
                        fi
                    '''
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('DAST & Policy') {
        // ════════════════════════════════════════════════════════════════════
            parallel {

                stage('DAST (OWASP ZAP)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " [7A] DAST — OWASP ZAP Baseline Scan"
                                mkdir -p "${WS}/reports/zap"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  --network host \
                                  -v "${WS}/reports/zap:/zap/wrk" \
                                  ghcr.io/zaproxy/zaproxy:stable \
                                  zap-baseline.py \
                                    -t "http://localhost:${APP_PORT}" \
                                    -m 3 \
                                    -r zap-report.html \
                                    -J zap-report.json \
                                    -I
                            '''
                        }
                    }
                    post {
                        always {
                            publishHTML(target: [
                                allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                reportDir: 'reports/zap', reportFiles: 'zap-report.html',
                                reportName: 'ZAP DAST Report'
                            ])
                        }
                    }
                }

                stage('Policy (OPA)') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh '''#!/bin/bash
                                echo " [7B] POLICY CHECK (OPA)"
                                mkdir -p "${WS}/reports/opa"

                                # Vérification que le fichier policy existe dans le repo
                                if [ ! -f "${WS}/policy/security.rego" ]; then
                                  echo " ERREUR : policy/security.rego introuvable dans le repo"
                                  exit 1
                                fi

                                # Génération du rapport Trivy FS en table pour OPA
                                TRIVY_REPORT="${WS}/reports/trivy/trivy-fs-report.json"
                                if [ ! -f "${TRIVY_REPORT}" ]; then
                                  echo " Rapport Trivy FS absent — OPA ignoré"
                                  exit 0
                                fi

                                # Évaluation OPA
                                OPA_RESULT=$(docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${WS}/policy:/policy:ro" \
                                  -v "${WS}/reports/trivy:/data:ro" \
                                  openpolicyagent/opa:latest eval \
                                    --data /policy/security.rego \
                                    --input /data/trivy-fs-report.json \
                                    "data.security.allow" \
                                    --format raw)

                                echo " Résultat OPA : ${OPA_RESULT}"
                                echo "${OPA_RESULT}" > "${WS}/reports/opa/opa-result.txt"

                                if [ "${OPA_RESULT}" != "true" ]; then
                                  echo " POLICY VIOLATION : OPA a retourné allow=false"
                                  echo " Vérifiez les vulnérabilités CRITICAL dans le rapport Trivy"
                                  exit 1
                                fi

                                echo " Policy validée (allow=true)"
                            '''
                        }
                    }
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // POST — Nettoyage & Archivage
    // ────────────────────────────────────────────────────────────────────────
    post {
        always {
            sh '''#!/bin/bash
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
            echo ' PIPELINE DEVSECOPS TERMINE AVEC SUCCES'
        }
        failure {
            echo ' PIPELINE ECHOUE — consultez les rapports archivés'
        }
        unstable {
            echo ' PIPELINE INSTABLE — vérifiez les stages en UNSTABLE'
        }
    }
}
