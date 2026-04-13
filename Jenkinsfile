/* ===========================================================================
 * PIPELINE DEVSECOPS — ARCHIVAGE DOC (VERSION FINALE v3)
 *
 * Corrections v3 :
 *   ✅ HOST_WS calculé dynamiquement (sed sur WORKSPACE) — plus de nom de job
 *      hardcodé → fonctionne quel que soit le nom du job Jenkins
 *   ✅ JENKINS_VOLUME_ROOT = '/var/lib/docker/volumes/jenkins_home/_data'
 *      (confirmé via docker inspect jenkins)
 *   ✅ Backslashes corrigés : \\\\ → \ dans tous les blocs sh
 *   ✅ Maven exécuté directement (tools directive) — résout le DinD path issue
 *   ✅ Outils sécurité (Gitleaks, Trivy, ZAP, OPA, Syft) restent en Docker
 *
 * PRÉ-REQUIS JENKINS :
 *   1. Maven "Maven-3.9" configuré dans Global Tool Configuration
 *   2. JDK "JDK-17" configuré dans Global Tool Configuration
 *   3. Credentials :
 *       ID "sonar-token"           → Secret Text
 *       ID "mysql-root-password"   → Secret Text
 *       ID "mysql-app-credentials" → Username/Password
 *   4. Plugins : SonarQube Scanner, HTML Publisher, JUnit
 *   5. Fichier policy/security.rego présent dans le repo Git
 * =========================================================================== */

pipeline {
    agent any

    tools {
        maven 'Maven-3.9'
        jdk   'JDK-17'
    }

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    environment {
        APP_PORT            = '8081'
        MYSQL_DATABASE      = 'archivage_db'
        DOCKER_NETWORK      = 'archivage-net'
        MYSQL_CONTAINER     = 'mysql-archivage'
        APP_CONTAINER       = 'app-archivage'
        APP_IMAGE           = "archivage-app:${BUILD_NUMBER}"
        // Racine du volume Jenkins sur l'hôte (confirmé via docker inspect jenkins)
        // Calcul dynamique dans chaque sh : HOST_WS = JENKINS_VOLUME_ROOT + WORKSPACE sans /var/jenkins_home
        JENKINS_VOLUME_ROOT = '/var/lib/docker/volumes/jenkins_home/_data'
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
                sh '''
                    echo "--------------------------------------------------------"
                    echo " [1/7] TESTS UNITAIRES (JUnit + JaCoCo)"
                    echo "--------------------------------------------------------"
                    mvn -q -B verify \
                        -Dmaven.repo.local="${JENKINS_HOME}/.m2/repository"
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
                sh '''
                    echo "--------------------------------------------------------"
                    echo " [2/7] COMPILATION (Maven package)"
                    echo "--------------------------------------------------------"
                    mvn -q -B -T 1C package -DskipTests \
                        -Dmaven.repo.local="${JENKINS_HOME}/.m2/repository"
                '''
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Analyses Statiques (SAST/SCA)') {
        // ════════════════════════════════════════════════════════════════════
            parallel {

                // ── Secrets ──────────────────────────────────────────────────
                stage('Secrets (Gitleaks)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                # Chemin hôte dynamique — indépendant du nom du job
                                HOST_WS="${JENKINS_VOLUME_ROOT}$(echo ${WORKSPACE} | sed 's|/var/jenkins_home||')"
                                echo " [3A] SCAN DES SECRETS (Gitleaks)"
                                echo " Workspace hote : ${HOST_WS}"
                                mkdir -p "${WORKSPACE}/reports/gitleaks"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${HOST_WS}:/workspace:ro" \
                                  zricethezav/gitleaks:latest detect \
                                    --source /workspace \
                                    --report-format json \
                                    --report-path /workspace/reports/gitleaks/gitleaks-report.json \
                                    --exit-code 0
                            '''
                        }
                    }
                }

                // ── SCA ───────────────────────────────────────────────────────
                stage('SCA (Trivy FS)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                HOST_WS="${JENKINS_VOLUME_ROOT}$(echo ${WORKSPACE} | sed 's|/var/jenkins_home||')"
                                echo " [3B] SCAN DES DEPENDANCES (Trivy FS)"
                                echo " Workspace hote : ${HOST_WS}"
                                mkdir -p "${WORKSPACE}/reports/trivy" "${WORKSPACE}/.trivycache"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${HOST_WS}:/workspace:rw" \
                                  -v "${HOST_WS}/.trivycache:/root/.cache/trivy" \
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

                // ── SAST ──────────────────────────────────────────────────────
                stage('SAST (SonarQube)') {
                // Maven direct — pas de docker run ici
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''
                                echo " [3C] ANALYSE QUALITE (SonarQube)"
                                mvn -q -B \
                                    -Dmaven.repo.local="${JENKINS_HOME}/.m2/repository" \
                                    org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                    -Dsonar.projectKey=archivage-Doc \
                                    -Dsonar.host.url=http://host.docker.internal:9000 \
                                    -Dsonar.login="${SONAR_TOKEN}" \
                                    -Dsonar.java.binaries=target/classes
                            '''
                        }
                    }
                }

                // ── SBOM ──────────────────────────────────────────────────────
                stage('SBOM (CycloneDX / Syft)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                HOST_WS="${JENKINS_VOLUME_ROOT}$(echo ${WORKSPACE} | sed 's|/var/jenkins_home||')"
                                echo " [3D] GENERATION SBOM (Syft)"
                                echo " Workspace hote : ${HOST_WS}"
                                mkdir -p "${WORKSPACE}/reports/sbom"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${HOST_WS}:/workspace:rw" \
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
                sh '''
                    echo "--------------------------------------------------------"
                    echo " [4/7] BUILD IMAGE DOCKER"
                    echo "--------------------------------------------------------"
                    docker build -t "${APP_IMAGE}" "${WORKSPACE}"
                    echo " Image construite : ${APP_IMAGE}"
                '''
            }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Trivy Image Scan') {
        // ════════════════════════════════════════════════════════════════════
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        HOST_WS="${JENKINS_VOLUME_ROOT}$(echo ${WORKSPACE} | sed 's|/var/jenkins_home||')"
                        echo " [5/7] SCAN IMAGE DOCKER (Trivy)"
                        echo " Workspace hote : ${HOST_WS}"
                        mkdir -p "${WORKSPACE}/reports/trivy" "${WORKSPACE}/.trivycache"

                        docker run --rm \
                          --security-opt no-new-privileges \
                          -v /var/run/docker.sock:/var/run/docker.sock \
                          -v "${HOST_WS}/.trivycache:/root/.cache/trivy" \
                          -v "${HOST_WS}/reports/trivy:/reports" \
                          ghcr.io/aquasecurity/trivy:latest image \
                            --severity HIGH,CRITICAL \
                            --format json \
                            --output /reports/trivy-image-report.json \
                            "${APP_IMAGE}"
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
                    sh '''
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

                        echo " Attente demarrage MySQL..."
                        for i in $(seq 1 20); do
                          docker exec "${MYSQL_CONTAINER}" \
                            mysqladmin ping -h localhost -u"${MYSQL_USER}" -p"${MYSQL_PASS}" --silent \
                            2>/dev/null && break
                          echo "  Tentative ${i}/20..."
                          sleep 5
                        done

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

                        echo " Attente demarrage Spring Boot..."
                        READY=0
                        for i in $(seq 1 24); do
                          STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
                            http://localhost:${APP_PORT}/actuator/health 2>/dev/null || echo "000")
                          if echo "${STATUS}" | grep -qE "^(200|302|401|403)$"; then
                            echo " Application disponible (HTTP ${STATUS})"
                            READY=1
                            break
                          fi
                          echo "  Tentative ${i}/24 - HTTP ${STATUS}"
                          sleep 5
                        done

                        if [ "${READY}" -ne 1 ]; then
                          echo " Timeout - logs :"
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
                            sh '''
                                HOST_WS="${JENKINS_VOLUME_ROOT}$(echo ${WORKSPACE} | sed 's|/var/jenkins_home||')"
                                echo " [7A] DAST - OWASP ZAP Baseline Scan"
                                echo " Workspace hote : ${HOST_WS}"
                                mkdir -p "${WORKSPACE}/reports/zap"

                                docker run --rm \
                                  --security-opt no-new-privileges \
                                  --network host \
                                  -v "${HOST_WS}/reports/zap:/zap/wrk" \
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
                            sh '''
                                HOST_WS="${JENKINS_VOLUME_ROOT}$(echo ${WORKSPACE} | sed 's|/var/jenkins_home||')"
                                echo " [7B] POLICY CHECK (OPA)"
                                echo " Workspace hote : ${HOST_WS}"
                                mkdir -p "${WORKSPACE}/reports/opa"

                                if [ ! -f "${WORKSPACE}/policy/security.rego" ]; then
                                  echo " ERREUR : policy/security.rego introuvable"
                                  exit 1
                                fi

                                TRIVY_REPORT="${WORKSPACE}/reports/trivy/trivy-fs-report.json"
                                if [ ! -f "${TRIVY_REPORT}" ]; then
                                  echo " Rapport Trivy absent - OPA ignore"
                                  exit 0
                                fi

                                OPA_RESULT=$(docker run --rm \
                                  --security-opt no-new-privileges \
                                  -v "${HOST_WS}/policy:/policy:ro" \
                                  -v "${HOST_WS}/reports/trivy:/data:ro" \
                                  openpolicyagent/opa:latest eval \
                                    --data /policy/security.rego \
                                    --input /data/trivy-fs-report.json \
                                    "data.security.allow" \
                                    --format raw)

                                echo " Resultat OPA : ${OPA_RESULT}"
                                echo "${OPA_RESULT}" > "${WORKSPACE}/reports/opa/opa-result.txt"

                                if [ "${OPA_RESULT}" != "true" ]; then
                                  echo " POLICY VIOLATION : allow=false"
                                  exit 1
                                fi
                                echo " Policy validee (allow=true)"
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            sh '''
                echo "--------------------------------------------------------"
                echo " NETTOYAGE"
                echo "--------------------------------------------------------"
                docker rm -f "${APP_CONTAINER}" "${MYSQL_CONTAINER}" 2>/dev/null || true
                docker network rm "${DOCKER_NETWORK}" 2>/dev/null || true
                docker rmi "${APP_IMAGE}" 2>/dev/null || true
            '''
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
        success  { echo ' PIPELINE DEVSECOPS TERMINE AVEC SUCCES' }
        failure  { echo ' PIPELINE ECHOUE - consultez les rapports' }
        unstable { echo ' PIPELINE INSTABLE - verifiez les stages UNSTABLE' }
    }
}
