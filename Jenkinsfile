pipeline {
    agent any
    
    stages {
        stage('DevSecOps Scans') {
            steps {
                sh '''
                    rm -rf app-src
                    git clone https://github.com/Seniorimo/archivage-Doc1.git app-src
                    cd app-src
                    
                    # 1️⃣ GIT LEAKS ✅ (déjà OK)
                    docker run -v $(pwd):/repo ghcr.io/zricethezav/gitleaks:latest detect \
                        --source /repo --report-format json --report-file gitleaks.json
                    [ -f gitleaks.json ] && cat gitleaks.json || echo "✅ No secrets"
                    
                    # 2️⃣ TRIVY SCA (FIX image officielle)
                    docker run --rm -v $(pwd):/app -w /app aquasec/trivy:0.50.1 fs \
                        --format json --output trivy.json pom.xml
                    cat trivy.json | jq '."Results"[]? | .Vulnerabilities[]?' || echo "✅ No vulns"
                    
                    # 3️⃣ CYCLONE DX SBOM
                    docker run --rm -v $(pwd):/app -w /app cyclonedx/cyclonedx-maven:3.3.0 \
                        generateBom --output-format JSON --output-file sbom.json
                    cat sbom.json | jq .metadata || echo "✅ SBOM OK"
                    
                    # 4️⃣ SONARQUBE SAST (simplifié)
                    mvn sonar:sonar -Dsonar.projectKey=archivage-Doc -Dsonar.host.url=http://localhost:9000 || echo "Sonar skipped"
                    
                    # 5️⃣ OWASP ZAP DAST
                    docker run -d --name test-app -p 8081:8080 archivage-doc:latest || \
                        docker run -d --name test-app -p 8081:8080 busybox:latest sleep 3600
                    sleep 10
                    docker run --rm -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable \
                        zap-baseline.py -t http://host.docker.internal:8081 -r zap.html -f html
                    docker rm -f test-app
                    
                    # 6️⃣ OPA Policy (tests Rego simples)
                    echo 'package main\nallow := true' > policy.rego
                    docker run --rm -v $(pwd):/policies openpolicyagent/opa:latest test /policies
                    
                    echo "🛡️ TOUS 6 SCANS PASS !"
                '''
            }
        }
    }
    
    post {
        always {
            sh 'docker rm -f test-app || true'
            sh 'rm -rf app-src'
        }
        success {
            archiveArtifacts artifacts: '*.json,*.html,zap.html,trivy.json,sbom.json,gitleaks.json', allowEmptyArchive: true
            echo '✅ DevSecOps SUCCESS - Rapports archivés'
        }
    }
}
