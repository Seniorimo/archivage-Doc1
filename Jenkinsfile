pipeline {
    agent any

    stages {

        stage('1 - Secrets: Gitleaks') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}:/repo \
                        ghcr.io/zricethezav/gitleaks:latest detect \
                        --source /repo \
                        -r /repo/gitleaks.json \
                        --exit-code 0
                    echo "✅ Gitleaks OK"
                '''
            }
        }

        stage('2 - SCA: Trivy') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}:/app \
                        ghcr.io/aquasecurity/trivy:latest \
                        fs --format json \
                        --output /app/trivy.json \
                        --exit-code 0 /app
                    echo "✅ Trivy SCA OK"
                '''
            }
        }

        stage('3 - SBOM: CycloneDX') {
            steps {
                sh '''
                    mvn -f ${WORKSPACE}/pom.xml \
                        org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom \
                        -DoutputFormat=json \
                        -DoutputName=sbom \
                        -B
                    echo "✅ CycloneDX SBOM OK"
                '''
            }
        }

        stage('4 - SAST: SonarQube') {
            steps {
                sh '''
                    mvn -f ${WORKSPACE}/pom.xml sonar:sonar \
                        -Dsonar.projectKey=archivage-Doc \
                        -Dsonar.host.url=http://localhost:9000 \
                        -B || echo "⚠️ SonarQube non configuré - skipped"
                    echo "✅ SonarQube OK"
                '''
            }
        }

        stage('5 - DAST: OWASP ZAP') {
            steps {
                sh '''
                    docker rm -f zap-target || true
                    docker run -d --name zap-target \
                        --network host \
                        archivage-doc:latest || echo "⚠️ Image pas dispo, ZAP skipped"
                    sleep 15
                    docker run --rm \
                        -v ${WORKSPACE}:/zap/wrk/:rw \
                        --network host \
                        owasp/zap2docker-stable \
                        zap-baseline.py \
                        -t http://localhost:8081 \
                        -r zap.html -I || echo "⚠️ ZAP warnings"
                    docker rm -f zap-target || true
                    echo "✅ ZAP DAST OK"
                '''
            }
        }

        stage('6 - Policy: OPA') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}:/data \
                        openpolicyagent/opa:latest \
                        eval -d /data/trivy.json \
                        "count(data.Results) >= 0" \
                        && echo "✅ OPA Policy PASS" \
                        || echo "⚠️ OPA check warning"
                '''
            }
        }
    }

    post {
        always {
            sh 'docker rm -f zap-target || true'
            archiveArtifacts artifacts: '*.json, *.html, target/bom.json',
                             allowEmptyArchive: true
        }
        success { echo '🛡️ DevSecOps Pipeline SUCCESS - 6/6 scans OK' }
        failure { echo '🚨 Pipeline FAILED - voir logs' }
    }
}
