/* ===========================================================================
 * PIPELINE DEVSECOPS — ARCHIVAGE DOC (VERSION FINALE)
 *
 * Corrections appliquées :
 *   [P0] ✅ --volumes-from jenkins → montages explicites -v (sécurité)
 *   [P0] ✅ Secrets MySQL via Jenkins Credentials Store (withCredentials)
 *   [P0] ✅ OPA : résultat capturé et enforced (exit 1 si allow=false)
 *   [P1] ✅ SonarQube Quality Gate bloquant (waitForQualityGate)
 *   [P1] ✅ Tests via "mvn verify" (fix JaCoCo — "jacoco:report" seul = erreur)
 *   [P1] ✅ Image Docker construite depuis Dockerfile + scan Trivy image
 *   [P1] ✅ Déploiement via l'image Docker (pas mvn spring-boot:run)
 *   [P2] ✅ policy/security.rego lu depuis le repo Git (pas généré inline)
 *   [P2] ✅ ZAP scan étendu à -m 3
 *   [P2] ✅ docker rmi en post-cleanup
 *   [P2] ✅ --security-opt no-new-privileges sur les conteneurs de test
 *
 * PRÉ-REQUIS JENKINS :
 *   - Jenkins home BIND-MONTÉ depuis l'hôte :
 *       docker run -v /host/jenkins_home:/var/jenkins_home jenkins/jenkins
 *   - Credentials configurés (Jenkins > Manage Credentials) :
 *       ID "sonar-token"           → Secret Text      (token SonarQube)
 *       ID "mysql-root-password"   → Secret Text      (password root MySQL)
 *       ID "mysql-app-credentials" → Username/Password (user + pass app)
 *   - Plugins : SonarQube Scanner, HTML Publisher, Warnings NG, JUnit
 *   - Fichier policy/security.rego présent dans le repo Git
 *
 * PRÉ-REQUIS pom.xml — JaCoCo doit être déclaré :
 *   <plugin>
 *     <groupId>org.jacoco</groupId>
 *     <artifactId>jacoco-maven-plugin</artifactId>
 *     <version>0.8.12</version>
 *     <executions>
 *       <execution><id>prepare-agent</id><goals><goal>prepare-agent</goal></goals></execution>
 *       <execution><id>report</id><phase>verify</phase><goals><goal>report</goal></goals></execution>
 *     </executions>
 *   </plugin>
 * =========================================================================== */

pipeline {
    agent any

    // ────────────────────────────────────────────────────────────────────────
    // CONFIGURATION GLOBALE
    // ────────────────────────────────────────────────────────────────────────
    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    environment {
        // ── Config non-sensible ────────────────────────────────────────────
        APP_PORT        = '8081'
        MYSQL_DATABASE  = 'archivage_db'
        DOCKER_NETWORK  = 'archivage-net'
        MYSQL_CONTAINER = 'mysql-archivage'
        APP_CONTAINER   = 'app-archivage'
        APP_IMAGE       = "archivage-app:${BUILD_NUMBER}"
        // ── Alias pour les montages Docker ─────────────────────────────────
        // WORKSPACE et JENKINS_HOME sont injectés automatiquement par Jenkins.
        // Prérequis : Jenkins home doit être BIND-MONTÉ depuis l'hôte.
        WS = "${WORKSPACE}"
        JH = "${JENKINS_HOME}"
    }

    // ────────────────────────────────────────────────────────────────────────
    // STAGES
    // ────────────────────────────────────────────────────────────────────────
    stages {

        // ════════════════════════════════════════════════════════════════════
        stage('Checkout') {
        // ════════════════════════════════════════════════════════════════════
            steps { checkout scm }
        }

        // ════════════════════════════════════════════════════════════════════
        stage('Tests Unitaires') {
        // ════════════════════════════════════════════════════════════════════
        // [FIX] "mvn verify" au lieu de "mvn test jacoco:report"
        //   → Maven ne résout "jacoco:" que si le plugin est dans les groupIds
        //   → "verify" lance : prepare-agent → test → jacoco:report automatiquement
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail
                    echo "--------------------------------------------------------"
                    echo " 🧪 [1/7] TESTS UNITAIRES (JUnit + JaCoCo)"
                    echo "--------------------------------------------------------"

                    docker run --rm \
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
        // -DskipTests : les tests ont déjà tourné au stage précédent
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail
                    echo "--------------------------------------------------------"
                    echo " ⚙️  [2/7] COMPILATION (Maven package)"
                    echo "--------------------------------------------------------"

                    docker run --rm \
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

                // ── Secrets ─────────────────────────────────────────────────
                stage('Secrets (Gitleaks)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " 🔍 [3A] SCAN DES SECRETS (Gitleaks)"
                                mkdir -p "${WS}/reports/gitleaks"

                                docker run --rm \
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

                // ── SCA ──────────────────────────────────────────────────────
                stage('SCA (Trivy FS)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " 📦 [3B] SCAN DES DÉPENDANCES (Trivy FS)"
                                mkdir -p "${WS}/reports/trivy" "${WS}/.trivycache"

                                docker run --rm \
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

                // ── SAST ─────────────────────────────────────────────────────
                stage('SAST (SonarQube)') {
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''#!/bin/bash
                                echo " 🧠 [3C] ANALYSE QUALITÉ (SonarQube)"

                                docker run --rm \
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

                // ── SBOM ─────────────────────────────────────────────────────
                stage('SBOM (CycloneDX)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " �
