/* ===========================================================================
 * PIPELINE DEVSECOPS — ARCHIVAGE DOC (VERSION CORRIGÉE)
 *
 * Corrections par rapport à la version initiale :
 *   [P0] ✅ --volumes-from jenkins remplacé par montages explicites (sécurité)
 *   [P0] ✅ Secrets MySQL gérés via Jenkins Credentials Store (withCredentials)
 *   [P0] ✅ OPA : résultat capturé et enforced (exit 1 si allow=false)
 *   [P1] ✅ SonarQube Quality Gate bloquant ajouté
 *   [P1] ✅ Tests unitaires (JUnit + JaCoCo) ajoutés comme première étape
 *   [P1] ✅ Image Docker construite depuis le Dockerfile + scan Trivy image
 *   [P1] ✅ Déploiement utilise l'image Docker (pas mvn spring-boot:run)
 *   [P2] ✅ policy/security.rego lu depuis le repo (pas généré inline)
 *   [P2] ✅ ZAP scan étendu à -m 3 (3 minutes)
 *   [P2] ✅ Image Docker nettoyée en post (docker rmi)
 *   [P2] ✅ --security-opt no-new-privileges sur les conteneurs de test
 *
 * PRÉ-REQUIS JENKINS :
 *   - Jenkins home BIND-MONTÉ depuis l'hôte :
 *       docker run -v /host/jenkins_home:/var/jenkins_home jenkins/jenkins
 *     (nécessaire pour que -v "${WORKSPACE}:..." fonctionne avec les sibling containers)
 *   - Credentials configurés dans Jenkins > Manage Credentials :
 *       ID "sonar-token"          → Secret Text    (token SonarQube)
 *       ID "mysql-root-password"  → Secret Text    (mot de passe root MySQL)
 *       ID "mysql-app-credentials"→ Username/Password (user/pass app MySQL)
 *   - Plugins : SonarQube Scanner, HTML Publisher, Warnings NG, JUnit
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
        timeout(time: 30, unit: 'MINUTES')             // Augmenté (tests + QG Sonar)
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    environment {
        // ── Config non-sensible (peut rester ici) ──────────────────────────
        APP_PORT        = '8081'
        MYSQL_DATABASE  = 'archivage_db'
        DOCKER_NETWORK  = 'archivage-net'
        MYSQL_CONTAINER = 'mysql-archivage'
        APP_CONTAINER   = 'app-archivage'
        APP_IMAGE       = "archivage-app:${BUILD_NUMBER}"

        // ── Alias pratiques pour les montages Docker ───────────────────────
        // WORKSPACE et JENKINS_HOME sont injectés automatiquement par Jenkins.
        // Ils correspondent à des chemins HÔTE si Jenkins home est bind-monté.
        WS  = "${WORKSPACE}"
        JH  = "${JENKINS_HOME}"
    }

    // ────────────────────────────────────────────────────────────────────────
    // EXÉCUTION DU PIPELINE
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
        // [AJOUT] Tests JUnit + couverture JaCoCo avant toute analyse.
        // Le pipeline s'arrête immédiatement si les tests échouent.
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
                          test jacoco:report
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
                    echo " ⚙️ [2/7] COMPILATION DU CODE (Maven package)"
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

                                # [FIX] Montage explicite workspace en :ro
                                # (était --volumes-from jenkins → exposait tous les volumes)
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

                // ── SCA (dépendances Maven) ──────────────────────────────────
                stage('SCA (Trivy FS)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " 📦 [3B] SCAN DES DÉPENDANCES (Trivy FS)"
                                mkdir -p "${WS}/reports/trivy" "${WS}/.trivycache"

                                # [FIX] --scanners vuln,secret (ajout du scan de secrets fichiers)
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

                // ── SAST (SonarQube) ─────────────────────────────────────────
                stage('SAST (SonarQube)') {
                    steps {
                        // [FIX] withCredentials au lieu de la variable d'env exposée
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''#!/bin/bash
                                echo " 🧠 [3C] ANALYSE QUALITÉ DU CODE (SonarQube)"

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

                // ── SBOM (CycloneDX) ─────────────────────────────────────────
                stage('SBOM (CycloneDX)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                echo " 📜 [3D] INVENTAIRE LOGICIEL (CycloneDX)"
                      
