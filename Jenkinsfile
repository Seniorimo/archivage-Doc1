 url=https://github.com/Seniorimo/archivage-Doc1
pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '15', artifactNumToKeepStr: '5'))
  }

  parameters {
    booleanParam(name: 'SKIP_SECURITY_GATE', defaultValue: false, description: 'Skip security policy gates (use with caution)')
    choice(name: 'TRIVY_SEVERITY', choices: ['CRITICAL,HIGH', 'CRITICAL,HIGH,MEDIUM', 'ALL'], defaultValue: 'CRITICAL,HIGH')
  }

  environment {
    // Application Configuration
    APP_NAME                    = 'archivage-doc'
    APP_IMAGE                   = "archivage-doc:${BUILD_NUMBER}"
    APP_CONTAINER               = 'archivage-doc-poc'
    APP_NETWORK                 = 'archivage-doc-net'
    DOCKER_NETWORK              = 'devsecops-net'

    // Security Scanning Tools
    MAVEN_IMAGE                 = 'maven:3.9.6-eclipse-temurin-17'
    GITLEAKS_IMAGE              = 'zricethezav/gitleaks:v8.21.2'
    TRIVY_IMAGE                 = 'aquasec/trivy:latest'
    OPA_IMAGE                   = 'openpolicyagent/opa:latest-static'
    ZAP_IMAGE                   = 'ghcr.io/zaproxy/zaproxy:stable'
    GRYPE_IMAGE                 = 'anchore/grype:latest'

    // Directories
    REPORT_DIR                  = 'reports'
    POLICY_DIR                  = 'policy'
    SCRIPT_DIR                  = 'scripts'
    BACKUP_DIR                  = 'backup'

    // SonarQube Configuration (Credentials from Jenkins)
    SONARQUBE_SERVER            = 'sonarqube'
    SONAR_PROJECT_KEY           = 'archivage-doc'
    SONAR_PROJECT_NAME          = 'archivage-doc'
    
    // Severity Levels
    CRITICAL_THRESHOLD          = '0'
    HIGH_THRESHOLD              = '5'
  }

  stages {
    stage('🔐 Initialization & Security Checks') {
      steps {
        script {
          echo "╔════��═══════════════════════════════════════════════════════╗"
          echo "║         DevSecOps Pipeline - Initialization                ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          sh '''
            set -eux
            
            # Create necessary directories
            mkdir -p "${REPORT_DIR}" "${POLICY_DIR}" "${SCRIPT_DIR}" "${BACKUP_DIR}"
            
            # Validate Docker daemon
            docker info > /dev/null 2>&1 || { echo "❌ Docker daemon not available"; exit 1; }
            
            # Clean up any stale containers
            docker ps -aq --filter "status=exited" | xargs -r docker rm -f || true
            
            # Display environment info
            echo "✅ Build Number: ${BUILD_NUMBER}"
            echo "✅ Workspace: ${WORKSPACE}"
            echo "✅ Jenkins URL: ${JENKINS_URL}"
          '''
        }
      }
    }

    stage('📥 Checkout SCM') {
      steps {
        checkout scm
        script {
          env.GIT_COMMIT_SHORT = sh(
            script: "git rev-parse --short HEAD",
            returnStdout: true
          ).trim()
          env.GIT_BRANCH = sh(
            script: "git rev-parse --abbrev-ref HEAD",
            returnStdout: true
          ).trim()
          
          echo "✅ Git Commit: ${GIT_COMMIT_SHORT}"
          echo "✅ Git Branch: ${GIT_BRANCH}"
        }
      }
    }

    stage('🧱 Brique 1: Secret Detection - Gitleaks') {
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  🔑 Scanning for hardcoded secrets and credentials...      ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          sh '''
            set -eux
            
            # Clean up any existing containers
            docker rm -f gitleaks-scan >/dev/null 2>&1 || true
            
            # Run Gitleaks with strict detection
            docker run --name gitleaks-scan \\
              --rm \\
              -v $(pwd):/repo \\
              ${GITLEAKS_IMAGE} \\
              detect \\
              --source=/repo \\
              --report-format sarif \\
              --report-path /repo/${REPORT_DIR}/gitleaks-results.sarif \\
              --exit-code 0 \\
              --verbose
            
            # Check for findings
            if [ -f "${REPORT_DIR}/gitleaks-results.sarif" ]; then
              LEAK_COUNT=$(jq '.runs[0].results | length' "${REPORT_DIR}/gitleaks-results.sarif" 2>/dev/null || echo 0)
              if [ "$LEAK_COUNT" -gt 0 ]; then
                echo "⚠️  WARNING: Found $LEAK_COUNT potential secrets!"
                echo "Please review and remediate before deployment."
                jq '.runs[0].results[] | .message.text' "${REPORT_DIR}/gitleaks-results.sarif"
              else
                echo "✅ No secrets detected!"
              fi
            fi
          '''
        }
      }
    }

    stage('🧱 Brique 2: SCA - Trivy Multi-Scanner') {
      parallel {
        stage('Trivy: Filesystem Scan') {
          steps {
            script {
              echo "╔════════════════════════════════════════════════════════════╗"
              echo "║  📦 Running Trivy filesystem vulnerability scan...         ║"
              echo "╚════════════════════════════════════════════════════════════╝"
              
              sh '''
                set -eux
                
                docker rm -f trivy-fs >/dev/null 2>&1 || true
                
                # Run Trivy filesystem scan (SARIF format for reporting)
                docker run --name trivy-fs \\
                  --rm \\
                  -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v $(pwd):/repo \\
                  ${TRIVY_IMAGE} \\
                  fs \\
                  --format sarif \\
                  --output /repo/${REPORT_DIR}/trivy-fs.sarif \\
                  --severity ${TRIVY_SEVERITY} \\
                  /repo
                
                # Also generate JSON for OPA policy evaluation
                docker run --name trivy-fs-json \\
                  --rm \\
                  -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v $(pwd):/repo \\
                  ${TRIVY_IMAGE} \\
                  fs \\
                  --format json \\
                  --output /repo/${REPORT_DIR}/trivy-fs.json \\
                  --severity ${TRIVY_SEVERITY} \\
                  /repo
                
                echo "✅ Trivy filesystem scan completed"
              '''
            }
          }
        }

        stage('Trivy: Dependency Check') {
          steps {
            script {
              echo "╔════════════════════════════════════════════════════════════╗"
              echo "║  🔍 Running Trivy dependency vulnerability scan...        ║"
              echo "╚════════════════════════════════════════════════════════════╝"
              
              sh '''
                set -eux
                
                docker rm -f trivy-dep >/dev/null 2>&1 || true
                
                # Scan pom.xml for known vulnerabilities
                docker run --name trivy-dep \\
                  --rm \\
                  -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v $(pwd):/repo \\
                  ${TRIVY_IMAGE} \\
                  config \\
                  --format sarif \\
                  --output /repo/${REPORT_DIR}/trivy-config.sarif \\
                  /repo
                
                echo "✅ Trivy dependency scan completed"
              '''
            }
          }
        }
      }
    }

    stage('🧱 Brique 3: SBOM Generation - CycloneDX') {
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  📋 Generating Software Bill of Materials (SBOM)...        ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          sh '''
            set -eux
            
            docker rm -f maven-sbom >/dev/null 2>&1 || true
            
            # Build with SBOM generation
            docker run \\
              --name maven-sbom \\
              --rm \\
              -v $(pwd):/app \\
              -v ~/.m2:/root/.m2 \\
              -w /app \\
              ${MAVEN_IMAGE} \\
              mvn -B \\
              clean install \\
              org.cyclonedx:cyclonedx-maven-plugin:2.9.0:makeBom \\
              -DskipTests \\
              -q
            
            # Extract SBOM files
            if [ -f target/bom.xml ]; then
              cp target/bom.xml ${REPORT_DIR}/bom.xml
              echo "✅ CycloneDX XML SBOM generated"
            fi
            
            if [ -f target/bom.json ]; then
              cp target/bom.json ${REPORT_DIR}/bom.json
              echo "✅ CycloneDX JSON SBOM generated"
            fi
          '''
        }
      }
    }

    stage('🧱 Brique 4: SAST - SonarQube Code Analysis') {
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  🔎 Running SonarQube SAST analysis...                     ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          withSonarQubeEnv("${SONARQUBE_SERVER}") {
            sh '''
              set -eux
              
              docker rm -f sonar-scan >/dev/null 2>&1 || true
              
              # Use SONAR_AUTH_TOKEN from Jenkins credentials
              docker run \\
                --name sonar-scan \\
                --rm \\
                -e SONAR_HOST_URL="${SONAR_HOST_URL}" \\
                -e SONAR_LOGIN="${SONAR_AUTH_TOKEN}" \\
                -v $(pwd):/app \\
                -v ~/.m2:/root/.m2 \\
                -w /app \\
                ${MAVEN_IMAGE} \\
                mvn -B \\
                verify \\
                sonar:sonar \\
                -DskipTests \\
                -Dsonar.projectKey=${SONAR_PROJECT_KEY} \\
                -Dsonar.projectName="${SONAR_PROJECT_NAME}" \\
                -Dsonar.host.url="${SONAR_HOST_URL}" \\
                -Dsonar.login="${SONAR_AUTH_TOKEN}" \\
                -Dsonar.exclusions="**/test/**" \\
                -Dsonar.qualitygate.wait=true \\
                -q
              
              echo "✅ SonarQube analysis completed"
            '''
          }
        }
        
        // Wait for SonarQube Quality Gate
        script {
          timeout(time: 5, unit: 'MINUTES') {
            waitForQualityGate abortPipeline: true
          }
        }
      }
    }

    stage('🧱 Brique 5: Container Build & Image Scanning') {
      parallel {
        stage('Build Docker Image') {
          steps {
            script {
              echo "╔════════════════════════════════════════════════════════════╗"
              echo "║  🐳 Building Docker image...                              ║"
              echo "╚════════════════════════════════════════════════════════════╝"
              
              sh '''
                set -eux
                
                # Build multi-stage Docker image
                docker build \\
                  --tag ${APP_IMAGE} \\
                  --tag archivage-doc:latest \\
                  --build-arg BUILD_NUMBER=${BUILD_NUMBER} \\
                  --build-arg GIT_COMMIT=${GIT_COMMIT_SHORT} \\
                  --label "build.number=${BUILD_NUMBER}" \\
                  --label "git.commit=${GIT_COMMIT_SHORT}" \\
                  --label "build.timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \\
                  .
                
                echo "✅ Docker image built: ${APP_IMAGE}"
              '''
            }
          }
        }

        stage('Scan Docker Image - Trivy') {
          steps {
            script {
              echo "╔════════════════════════════════════════════════════════════╗"
              echo "║  🔍 Scanning Docker image with Trivy...                  ║"
              echo "╚════════════════════════════════════════════════════════════╝"
              
              sh '''
                set -eux
                
                docker rm -f trivy-image >/dev/null 2>&1 || true
                
                # Scan built image
                docker run --name trivy-image \\
                  --rm \\
                  -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v $(pwd)/${REPORT_DIR}:/reports \\
                  ${TRIVY_IMAGE} \\
                  image \\
                  --format sarif \\
                  --output /reports/trivy-image.sarif \\
                  --severity ${TRIVY_SEVERITY} \\
                  ${APP_IMAGE}
                
                # Also generate JSON
                docker run --name trivy-image-json \\
                  --rm \\
                  -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v $(pwd)/${REPORT_DIR}:/reports \\
                  ${TRIVY_IMAGE} \\
                  image \\
                  --format json \\
                  --output /reports/trivy-image.json \\
                  --severity ${TRIVY_SEVERITY} \\
                  ${APP_IMAGE}
                
                echo "✅ Docker image scanned successfully"
              '''
            }
          }
        }

        stage('Scan Docker Image - Grype') {
          steps {
            script {
              echo "╔══════════════════════════════════════════════���═════════════╗"
              echo "║  🔐 Scanning Docker image with Grype...                   ║"
              echo "╚════════════════════════════════════════════════════════════╝"
              
              sh '''
                set -eux
                
                docker rm -f grype-scan >/dev/null 2>&1 || true
                
                # Additional scan with Grype for enhanced coverage
                docker run --name grype-scan \\
                  --rm \\
                  -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v $(pwd)/${REPORT_DIR}:/reports \\
                  ${GRYPE_IMAGE} \\
                  --output sarif \\
                  --file /reports/grype-results.sarif \\
                  docker://${APP_IMAGE} || true
                
                echo "✅ Grype image scan completed"
              '''
            }
          }
        }
      }
    }

    stage('🧱 Brique 6: DAST - OWASP ZAP Dynamic Testing') {
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  🔓 Running OWASP ZAP dynamic security testing...          ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          sh '''
            set -eux
            
            # Cleanup
            docker rm -f ${APP_CONTAINER} >/dev/null 2>&1 || true
            docker network rm ${APP_NETWORK} >/dev/null 2>&1 || true
            
            # Create isolated network
            docker network create ${APP_NETWORK}
            
            # Run application container
            docker run -d \\
              --name ${APP_CONTAINER} \\
              --network ${APP_NETWORK} \\
              --memory=512m \\
              --memory-reservation=256m \\
              --cpus=0.5 \\
              --read-only \\
              --cap-drop=ALL \\
              --cap-add=NET_BIND_SERVICE \\
              --security-opt=no-new-privileges:true \\
              ${APP_IMAGE}
            
            echo "⏳ Waiting for application startup (30s)..."
            sleep 30
            
            # Verify app is responding
            for i in {1..10}; do
              if docker exec ${APP_CONTAINER} wget -q -O- http://localhost:8080/actuator/health > /dev/null 2>&1; then
                echo "✅ Application is healthy"
                break
              fi
              if [ $i -eq 10 ]; then
                echo "❌ Application failed to start"
                docker logs ${APP_CONTAINER} --tail 50
                exit 1
              fi
              sleep 3
            done
          '''
        }
        
        // OWASP ZAP Baseline Scan
        sh '''
          set -eux
          
          docker rm -f zap-scan >/dev/null 2>&1 || true
          
          # Run ZAP baseline scan
          docker run --name zap-scan \\
            --rm \\
            --network ${APP_NETWORK} \\
            -v $(pwd)/${REPORT_DIR}:/zap/wrk/:rw \\
            ${ZAP_IMAGE} \\
            zap-baseline.py \\
            -t "http://${APP_CONTAINER}:8080" \\
            -r /zap/wrk/zap-baseline-report.html \\
            -x /zap/wrk/zap-baseline-report.xml \\
            -d || true
          
          echo "✅ OWASP ZAP baseline scan completed"
        '''
        
        // Convert ZAP XML to SARIF
        sh '''
          set -eux
          
          if [ ! -f "${SCRIPT_DIR}/zap_xml_to_sarif.py" ]; then
            cat > "${SCRIPT_DIR}/zap_xml_to_sarif.py" << 'EOF'
#!/usr/bin/env python3
import json
import xml.etree.ElementTree as ET
import sys
from datetime import datetime

def zap_xml_to_sarif(xml_file, sarif_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP ZAP",
                    "version": "2.14.0",
                    "informationUri": "https://www.zaproxy.org"
                }
            },
            "results": []
        }]
    }
    
    for alert in root.findall(".//alert"):
        name = alert.findtext("name", "Unknown")
        severity = alert.findtext("riskcode", "0")
        description = alert.findtext("desc", "")
        
        result = {
            "ruleId": name.replace(" ", "_"),
            "message": {"text": description},
            "level": ["none", "note", "warning", "warning", "error"][int(severity)] if severity.isdigit() else "warning"
        }
        sarif["runs"][0]["results"].append(result)
    
    with open(sarif_file, 'w') as f:
        json.dump(sarif, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: zap_xml_to_sarif.py <input.xml> <output.sarif>")
        sys.exit(1)
    zap_xml_to_sarif(sys.argv[1], sys.argv[2])
EOF
            chmod +x "${SCRIPT_DIR}/zap_xml_to_sarif.py"
          fi
          
          # Convert to SARIF
          python3 "${SCRIPT_DIR}/zap_xml_to_sarif.py" \\
            "${REPORT_DIR}/zap-baseline-report.xml" \\
            "${REPORT_DIR}/zap-results.sarif" || true
          
          echo "✅ ZAP report converted to SARIF"
        '''
      }
    }

    stage('🧱 Brique 7: Policy Gate - OPA Conftest') {
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  ⚖️  Evaluating security policies with OPA...             ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          // Generate OPA policy if it doesn't exist
          sh '''
            set -eux
            
            if [ ! -f "${POLICY_DIR}/security.rego" ]; then
              cat > "${POLICY_DIR}/security.rego" << 'EOF'
package security

# Deny critical vulnerabilities
deny[msg] {
    input.runs[0].results[_].level == "error"
    msg := sprintf("Critical vulnerability found: %s", [input.runs[0].results[_].message.text])
}

# Warn on high severity
warn[msg] {
    input.runs[0].results[_].level == "warning"
    msg := sprintf("High severity issue found: %s", [input.runs[0].results[_].message.text])
}

# Allow if no critical issues
allow {
    count(deny) == 0
}
EOF
            fi
          '''
          
          // Evaluate Trivy results
          sh '''
            set -eux
            
            docker rm -f opa-eval >/dev/null 2>&1 || true
            
            # Evaluate policy against Trivy filesystem results
            docker run --name opa-eval \\
              --rm \\
              -v $(pwd)/${REPORT_DIR}:/reports \\
              -v $(pwd)/${POLICY_DIR}:/policy \\
              ${OPA_IMAGE} \\
              eval \\
              --format pretty \\
              --data /policy/security.rego \\
              --input /reports/trivy-fs.json \\
              "data.security.deny" || true
            
            echo "✅ OPA policy evaluation completed"
          '''
        }
      }
    }

    stage('📊 Publish Security Reports') {
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  📈 Publishing security reports...                        ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          sh '''
            set -eux
            
            # Generate HTML index
            cat > ${REPORT_DIR}/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Pipeline Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .report { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        a { color: #0066cc; }
    </style>
</head>
<body>
    <h1>🔐 DevSecOps Pipeline Report</h1>
    <div class="report">
        <h2>Security Scans</h2>
        <ul>
            <li><a href="gitleaks-results.sarif">Gitleaks (Secrets Detection)</a></li>
            <li><a href="trivy-fs.sarif">Trivy (Filesystem Scan)</a></li>
            <li><a href="trivy-image.sarif">Trivy (Image Scan)</a></li>
            <li><a href="zap-baseline-report.html">OWASP ZAP (DAST)</a></li>
            <li><a href="grype-results.sarif">Grype (Vulnerability Scan)</a></li>
        </ul>
    </div>
    <div class="report">
        <h2>Bill of Materials</h2>
        <ul>
            <li><a href="bom.xml">CycloneDX (XML)</a></li>
            <li><a href="bom.json">CycloneDX (JSON)</a></li>
        </ul>
    </div>
</body>
</html>
EOF
          '''
        }
        
        // Record all SARIF results
        recordIssues(
          enabledForFailure: true,
          tools: [
            sarif(id: 'gitleaks', name: 'Gitleaks Secrets', pattern: 'reports/gitleaks-results.sarif'),
            sarif(id: 'trivy-fs', name: 'Trivy Filesystem', pattern: 'reports/trivy-fs.sarif'),
            sarif(id: 'trivy-image', name: 'Trivy Image', pattern: 'reports/trivy-image.sarif'),
            sarif(id: 'trivy-config', name: 'Trivy Config', pattern: 'reports/trivy-config.sarif'),
            sarif(id: 'zap', name: 'OWASP ZAP', pattern: 'reports/zap-results.sarif'),
            sarif(id: 'grype', name: 'Grype', pattern: 'reports/grype-results.sarif')
          ]
        )
        
        // Archive all reports and artifacts
        archiveArtifacts(
          artifacts: 'reports/**, target/*.jar, policy/**, scripts/**',
          allowEmptyArchive: true,
          fingerprint: true
        )
        
        // Publish HTML reports
        publishHTML([
          reportDir: 'reports/',
          reportFiles: 'index.html',
          reportName: '📊 DevSecOps Security Report',
          allowMissing: false,
          alwaysLinkToLastBuild: true,
          keepAll: true
        ])
        
        publishHTML([
          reportDir: 'reports/',
          reportFiles: 'zap-baseline-report.html',
          reportName: '🔓 OWASP ZAP Report',
          allowMissing: true,
          alwaysLinkToLastBuild: false,
          keepAll: true
        ])
      }
    }

    stage('✅ Security Gate Decision') {
      when {
        expression { !params.SKIP_SECURITY_GATE }
      }
      steps {
        script {
          echo "╔════════════════════════════════════════════════════════════╗"
          echo "║  🔐 Evaluating Security Gate...                           ║"
          echo "╚════════════════════════════════════════════════════════════╝"
          
          sh '''
            set -eux
            
            CRITICAL_COUNT=$(jq '.runs[0].results | map(select(.level == "error")) | length' ${REPORT_DIR}/trivy-fs.json 2>/dev/null || echo 0)
            HIGH_COUNT=$(jq '.runs[0].results | map(select(.level == "warning")) | length' ${REPORT_DIR}/trivy-fs.json 2>/dev/null || echo 0)
            
            echo "📊 Security Summary:"
            echo "   Critical Issues: $CRITICAL_COUNT (Threshold: ${CRITICAL_THRESHOLD})"
            echo "   High Issues: $HIGH_COUNT (Threshold: ${HIGH_THRESHOLD})"
            
            if [ "$CRITICAL_COUNT" -gt "${CRITICAL_THRESHOLD}" ]; then
              echo "❌ Critical issues exceed threshold!"
              exit 1
            fi
            
            if [ "$HIGH_COUNT" -gt "${HIGH_THRESHOLD}" ]; then
              echo "⚠️  High severity issues exceed threshold!"
              exit 1
            fi
            
            echo "✅ Security gate passed!"
          '''
        }
      }
    }
  }

  post {
    always {
      script {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  🧹 Cleanup & Finalization                               ║"
        echo "╚════════��═══════════════════════════════════════════════════╝"
        
        sh '''
          # Cleanup running containers
          docker rm -f ${APP_CONTAINER} >/dev/null 2>&1 || true
          docker network rm ${APP_NETWORK} >/dev/null 2>&1 || true
          
          # Remove all security scan containers
          docker rm -f gitleaks-scan trivy-fs trivy-fs-json trivy-dep \\
            trivy-image trivy-image-json grype-scan sonar-scan \\
            maven-sbom zap-scan zap-convert opa-eval >/dev/null 2>&1 || true
          
          # Prune dangling images
          docker image prune -f --filter "dangling=true" >/dev/null 2>&1 || true
          
          echo "✅ Cleanup completed"
        '''
      }
    }

    success {
      script {
        echo "✅ Pipeline execution completed successfully!"
        emailext(
          to: '${DEFAULT_RECIPIENTS}',
          subject: "✅ DevSecOps Pipeline Success - ${APP_NAME} #${BUILD_NUMBER}",
          body: """
          The DevSecOps pipeline completed successfully!
          
          Build: ${BUILD_NUMBER}
          Git Commit: ${GIT_COMMIT_SHORT}
          Git Branch: ${GIT_BRANCH}
          
          📊 Reports: ${BUILD_URL}artifact/
          
          All security gates passed.
          """,
          attachmentsPattern: 'reports/**/*.sarif'
        )
      }
    }

    failure {
      script {
        echo "❌ Pipeline execution failed!"
        emailext(
          to: '${DEFAULT_RECIPIENTS}',
          subject: "❌ DevSecOps Pipeline Failure - ${APP_NAME} #${BUILD_NUMBER}",
          body: """
          The DevSecOps pipeline failed!
          
          Build: ${BUILD_NUMBER}
          Git Commit: ${GIT_COMMIT_SHORT}
          Git Branch: ${GIT_BRANCH}
          
          ❌ Check the logs: ${BUILD_URL}console
          📊 Reports: ${BUILD_URL}artifact/
          
          Please review the security findings and remediate.
          """,
          attachmentsPattern: 'reports/**/*.sarif'
        )
      }
    }

    unstable {
      script {
        echo "⚠️  Pipeline completed with warnings!"
        echo "Review security findings before proceeding to production."
      }
    }
  }
}
