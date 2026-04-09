pipeline {
    agent any

    environment {
        // Nom de la config SonarQube dans Jenkins (Admin > System > SonarQube)
        SONAR_CONFIG_NAME = 'SonarQubeServer' 
        SCAN_REPORTS      = 'reports'
    }

    stages {
        stage('📥 Initialisation') {
            steps {
                sh "mkdir -p ${SCAN_REPORTS} policy scripts"
                echo "🚀 Lancement du Pipeline DevSecOps pour : ${env.JOB_NAME}"
            }
        }

        stage('🧱 Brique 1: Secret Detection (Gitleaks)') {
            steps {
                sh """
                    docker run --rm -v ${WORKSPACE}:/src zricethezav/gitleaks:v8.21.2 detect \
                    --source=/src --report-format sarif --report-path /src/${SCAN_REPORTS}/gitleaks-results.sarif --exit-code 0
                """
            }
        }

        stage('🧱 Brique 2: SCA (Trivy)') {
            steps {
                // Scan des vulnérabilités dans les dépendances (pom.xml)
                sh """
                    docker run --rm -v ${WORKSPACE}:/src -v /var/run/docker.sock:/var/run/docker.sock \
                    ghcr.io/aquasecurity/trivy:latest fs --scanners vuln --format sarif --output /src/${SCAN_REPORTS}/trivy-results.sarif /src
                """
            }
        }

        stage('🧱 Brique 3 & 4: SAST & SBOM') {
            steps {
                // Utilisation du plugin Jenkins SonarQube pour l'auth automatique
                withSonarQubeEnv("${SONAR_CONFIG_NAME}") {
                    sh """
                        docker run --rm -v ${WORKSPACE}:/app -w /app maven:3.9.6-eclipse-temurin-17 \
                        mvn -B clean install org.cyclonedx:cyclonedx-maven-plugin:2.9.0:makeBom sonar:sonar \
                        -DskipTests \
                        -Dsonar.projectKey=archivage-doc \
                        -Dsonar.projectName=archivage-doc
                    """
                }
            }
        }

        stage('🧱 Brique 5: DAST (OWASP ZAP)') {
            steps {
                echo "🔍 Lancement du scan dynamique..."
                // On lance un scan baseline rapide sur l'URL de test
                // Remplace 'http://votre-app-url' par l'IP de ton appli
                sh """
                    docker run --rm -v ${WORKSPACE}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
                    zap-baseline.py -t http://10.0.0.237:8080 -r zap-report.html || true
                """
            }
        }

        stage('🧱 Brique 6: Policy as Code (OPA)') {
            steps {
                echo "⚖️ Vérification des politiques de sécurité..."
                // Ici tu compares tes rapports SARIF avec tes règles OPA
                sh "echo 'OPA Evaluation logic goes here'" 
            }
        }

        stage('📊 Publication') {
            steps {
                echo "✅ Scans terminés. Archivage des rapports..."
                archiveArtifacts artifacts: "${SCAN_REPORTS}/*", allowEmptyArchive: true
            }
        }
    }

    post {
        always {
            sh "docker network rm archivage-sec-net || true"
            deleteDir() // Nettoyage du workspace
        }
        success {
            echo "🛡️ Pipeline DevSecOps réussi !"
        }
        failure {
            echo "❌ Échec du pipeline. Vérifie les logs de Sonar ou Trivy."
        }
    }
}
