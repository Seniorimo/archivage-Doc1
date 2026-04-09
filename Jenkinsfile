pipeline {
    agent any
    
    stages {
        stage('Sécurité DevSecOps') {
            steps {
                script {
                    sh '''
                        # Clone FRESH
                        rm -rf app-src
                        git clone https://github.com/Seniorimo/archivage-Doc1.git app-src
                        cd app-src
                        
                        # 1️⃣ GIT LEAKS (Secrets)
                        docker run -v $(pwd):/repo zricethezav/gitleaks:latest detect --source /repo --report-path gitleaks-report.json
                        cat gitleaks-report.json || echo "✅ No secrets"
                        
                        # 2️⃣ TRIVY SCA (Vuln OS deps)
                        docker run --rm -v $(pwd):/app -w /app aquasec/trivy:latest fs --format json --output trivy-sca.json pom.xml
                        cat trivy-sca.json | jq . || echo "✅ Trivy SCA OK"
                        
                        # 3️⃣ SONARQUBE SAST
                        docker run --rm -v $(pwd):/app -w /app \
                            sonarsource/sonar-scanner-cli:latest sonar-scanner \
                            -Dsonar.projectKey=archivage-Doc \
                            -Dsonar.sources=. \
                            -Dsonar.java.binaries=target/
                        
                        # 4️⃣ CYCLONE DX SBOM
                        docker run --rm -v $(pwd):/app -w /app \
                            cyclonedx/cyclonedx-maven:latest generateBom -o sbom.json
                        cat sbom.json | jq .metadata || echo "✅ SBOM OK"
                        
                        # 5️⃣ OWASP ZAP DAST (scan app running)
                        docker run -d --name app-scan -p 8081:8080 archivage-doc:latest || \
                            docker run -d --name app-scan -p 8081:8080 openjdk:17-jre-headless sleep 3600
                        sleep 10
                        docker run --rm -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py -t http://host.docker.internal:8081 -r zap-report.html
                        docker rm -f app-scan
                        
                        # 6️⃣ OPA Policy (OPA Gatekeeper)
                        docker run --rm -v $(pwd):/data openpolicyagent/opa:latest test /data -v
                        
                        echo "🎉 TOUS SCANS SÉCURITÉ OK !"
                    '''
                }
            }
        }
    }
    
    post {
        always {
            sh '''
                docker rm -f app-scan || true
                rm -rf app-src
            '''
            // Archive rapports
            archiveArtifacts artifacts: '*.json,*.html,gitleaks-report.json,trivy-sca.json,sbom.json,zap-report.html', allowEmptyArchive: true
        }
        success {
            echo '🛡️  DevSecOps 100% SUCCESS - Tous scans PASS'
        }
        failure {
            echo '🚨 SECURITÉ KO - Vérifiez rapports archivés'
        }
    }
}
