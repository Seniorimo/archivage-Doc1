pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  environment {
    MAVEN_IMAGE        = 'maven:3.9.6-eclipse-temurin-17'
    GITLEAKS_IMAGE     = 'zricethezav/gitleaks:v8.21.2'
    TRIVY_IMAGE        = 'ghcr.io/aquasecurity/trivy:latest'
    OPA_IMAGE          = 'openpolicyagent/opa:latest-static'
    ZAP_IMAGE          = 'ghcr.io/zaproxy/zaproxy:stable'

    APP_IMAGE          = "archivage-sec:${BUILD_NUMBER}"
    APP_CONTAINER      = 'archivage-sec-poc'
    APP_NETWORK        = 'archivage-sec-net'

    REPORT_DIR         = 'reports'
    POLICY_DIR         = 'policy'
    SCRIPT_DIR         = 'scripts'

    // ⚠️ بدل هاد الجوج بمعلومات SonarQube ديالك
    SONAR_PROJECT_KEY  = 'archivage-doc'
    SONAR_PROJECT_NAME = 'archivage-doc'
    SONAR_URL          = 'http://10.0.0.237:9000'
    SONAR_TOKEN        = 'sqa_xxxxxxxxxxxxxxxxxxx'
  }

  stages {

    stage('📥 Initialisation') {
      steps {
        checkout scm
        sh '''
          set -eux
          mkdir -p "${REPORT_DIR}" "${POLICY_DIR}" "${SCRIPT_DIR}"
        '''
        
        writeFile file: "${POLICY_DIR}/trivy.rego", text: '''
package trivy
deny[msg] {
  some i
  result := input.Results[i]
  some j
  vuln := result.Vulnerabilities[j]
  vuln.Severity == "CRITICAL"
  msg := sprintf("Critical vulnerability detected: %s in %s (%s)", [vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion])
}
'''
        writeFile file: "${SCRIPT_DIR}/zap_xml_to_sarif.py", text: '''
import json, os, sys
import xml.etree.ElementTree as ET

input_file = sys.argv[1]
output_file = sys.argv[2]

def empty_sarif():
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "OWASP ZAP", "rules": []}}, "results": []}]}

if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
    with open(output_file, "w", encoding="utf-8") as f: json.dump(empty_sarif(), f)
    sys.exit(0)

tree = ET.parse(input_file)
rules, results, seen_rules = [], [], set()

for item in tree.getroot().findall(".//alertitem"):
    pluginid = item.findtext("pluginid", default="ZAP-UNKNOWN")
    alert = item.findtext("alert", default="ZAP Alert")
    riskdesc = item.findtext("riskdesc", default="Info")
    
    if pluginid not in seen_rules:
        seen_rules.add(pluginid)
        rules.append({"id": pluginid, "name": alert, "shortDescription": {"text": alert}})
    
    for inst in item.findall(".//instance"):
        results.append({"ruleId": pluginid, "level": "warning", "message": {"text": alert}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": inst.findtext("uri", default="")}}}]})

with open(output_file, "w", encoding="utf-8") as f:
    json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "OWASP ZAP", "rules": rules}}, "results": results}]}, f)
'''
      }
    }

    stage('🧱 Brique 1: Secret Detection (Gitleaks)') {
      steps {
        sh '''
          docker create --name gitleaks-scan -w /src "${GITLEAKS_IMAGE}" detect --no-git --source=/src --report-format sarif --report-path /tmp/gitleaks-results.sarif --exit-code 0
          tar --exclude=.git -cf - . | docker cp - gitleaks-scan:/src
          docker start -a gitleaks-scan || true
          docker cp gitleaks-scan:/tmp/gitleaks-results.sarif "${REPORT_DIR}/gitleaks-results.sarif" || true
          docker rm -f gitleaks-scan
        '''
      }
    }

    stage('🧱 Brique 2: SCA (Trivy)') {
      steps {
        sh '''
          docker create --name trivy-scan -w /src "${TRIVY_IMAGE}" fs --scanners vuln --format sarif --output /tmp/trivy-results.sarif /src
          tar --exclude=.git -cf - . | docker cp - trivy-scan:/src
          docker start -a trivy-scan || true
          docker cp trivy-scan:/tmp/trivy-results.sarif "${REPORT_DIR}/trivy-results.sarif" || true
          docker rm -f trivy-scan

          docker create --name trivy-json -w /src "${TRIVY_IMAGE}" fs --scanners vuln --format json --output /tmp/trivy-results.json /src
          tar --exclude=.git -cf - . | docker cp - trivy-json:/src
          docker start -a trivy-json || true
          docker cp trivy-json:/tmp/trivy-results.json "${REPORT_DIR}/trivy-results.json" || true
          docker rm -f trivy-json
        '''
      }
    }

    stage('🧱 Brique 3 & 4: SAST & SBOM (SonarQube & CycloneDX)') {
      steps {
        sh '''
          docker create --name maven-sec -w /app "${MAVEN_IMAGE}" sh -lc "mvn -B clean install org.cyclonedx:cyclonedx-maven-plugin:2.9.0:makeBom sonar:sonar -DskipTests -Dsonar.projectKey=${SONAR_PROJECT_KEY} -Dsonar.projectName=${SONAR_PROJECT_NAME} -Dsonar.host.url=${SONAR_URL} -Dsonar.token=${SONAR_TOKEN}"
          tar --exclude=.git -cf - . | docker cp - maven-sec:/app
          docker start -a maven-sec
          
          docker cp maven-sec:/app/target/bom.json "${REPORT_DIR}/bom.json" || true
          docker rm -f maven-sec
        '''
      }
    }

    stage('🧱 Brique 5: DAST (OWASP ZAP)') {
      steps {
        sh '''
          docker build -t "${APP_IMAGE}" .
          docker network create "${APP_NETWORK}" || true
          docker run -d --name "${APP_CONTAINER}" --network "${APP_NETWORK}" "${APP_IMAGE}"
          sleep 20 

          docker create --name zap-scan --network "${APP_NETWORK}" "${ZAP_IMAGE}" zap-baseline.py -t "http://${APP_CONTAINER}:8080" -x zap-report.xml -I
          docker start -a zap-scan || true
          docker cp zap-scan:/zap/wrk/zap-report.xml "${REPORT_DIR}/zap-report.xml" || true
          docker rm -f zap-scan
          
          docker create --name zap-convert -w /work python:3.12-alpine sh -lc "python /work/zap_xml_to_sarif.py /work/zap-report.xml /work/zap-results.sarif"
          docker cp "${SCRIPT_DIR}/zap_xml_to_sarif.py" zap-convert:/work/zap_xml_to_sarif.py
          docker cp "${REPORT_DIR}/zap-report.xml" zap-convert:/work/zap-report.xml
          docker start -a zap-convert || true
          docker cp zap-convert:/work/zap-results.sarif "${REPORT_DIR}/zap-results.sarif" || true
          docker rm -f zap-convert
        '''
      }
    }

    stage('🧱 Brique 6: Policy as Code (OPA Gate)') {
      steps {
        sh '''
          docker create --name opa-eval -w /work "${OPA_IMAGE}" eval --fail-defined --format pretty --data /work/trivy.rego --input /work/trivy-results.json "data.trivy.deny"
          docker cp "${POLICY_DIR}/trivy.rego" opa-eval:/work/trivy.rego
          docker cp "${REPORT_DIR}/trivy-results.json" opa-eval:/work/trivy-results.json
          docker start -a opa-eval
          docker rm -f opa-eval
        '''
      }
    }

    stage('📊 Publication des Rapports') {
      steps {
        recordIssues enabledForFailure: true, tools: [
          sarif(id: 'trivy', name: 'Trivy SCA', pattern: 'reports/trivy-results.sarif'),
          sarif(id: 'gitleaks', name: 'Gitleaks Secrets', pattern: 'reports/gitleaks-results.sarif'),
          sarif(id: 'zap', name: 'OWASP ZAP DAST', pattern: 'reports/zap-results.sarif')
        ]
        archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
      }
    }
  }

  post {
    always {
      sh '''
        docker rm -f gitleaks-scan trivy-scan trivy-json maven-sec zap-scan zap-convert opa-eval "${APP_CONTAINER}" >/dev/null 2>&1 || true
        docker network rm "${APP_NETWORK}" >/dev/null 2>&1 || true
      '''
    }
    success { echo '✅ Pipeline de Sécurité terminée.' }
    failure { echo '❌ Pipeline de Sécurité en échec.' }
  }
}
// <-- تأكد بلي كوبيتي هاد المعقوفة اللخرة اللي كتسد Pipeline كاملة!
