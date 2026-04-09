pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  environment {
    // 🛠️ أدوات الأمن (Images Docker)
    MAVEN_IMAGE        = 'maven:3.9.6-eclipse-temurin-17'
    GITLEAKS_IMAGE     = 'zricethezav/gitleaks:v8.21.2'
    TRIVY_IMAGE        = 'aquasec/trivy:latest'
    OPA_IMAGE          = 'openpolicyagent/opa:latest-static'
    ZAP_IMAGE          = 'ghcr.io/zaproxy/zaproxy:stable'

    // 📦 إعدادات التطبيق الوهمي (للتجربة فقط)
    APP_IMAGE          = "archivage-sec:${BUILD_NUMBER}"
    APP_CONTAINER      = 'archivage-sec-poc'
    APP_NETWORK        = 'archivage-sec-net'

    // 📂 المجلدات
    REPORT_DIR         = 'reports'
    POLICY_DIR         = 'policy'
    SCRIPT_DIR         = 'scripts'

    // 🔍 إعدادات SonarQube (بدل هادو بالمعلومات ديالك)
    SONAR_PROJECT_KEY  = 'archivage-doc'
    SONAR_PROJECT_NAME = 'archivage-doc'
    SONAR_URL          = 'http://192.168.x.x:9000' // <--- حط الـ IP الحقيقي هنا
    SONAR_TOKEN        = 'sqa_xxxxxxxxxxxxx'       // <--- حط الـ Token ديالك هنا
  }

  stages {

    stage('📥 Initialisation') {
      steps {
        checkout scm
        sh '''
          set -eux
          mkdir -p "${REPORT_DIR}" "${POLICY_DIR}" "${SCRIPT_DIR}"
        '''
        
        // --- 📝 صناعة سكريبتات المساعدة أوتوماتيكيا ---
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
        // سكريبت تحويل ZAP إلى SARIF
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
          docker create --name gitleaks-scan "${GITLEAKS_IMAGE}" detect --source=/src --report-format sarif --report-path /tmp/gitleaks-results.sarif --exit-code 0
          docker start gitleaks-scan
          docker exec gitleaks-scan sh -c "mkdir -p /src"
          tar --exclude=.git -cf - . | docker cp - gitleaks-scan:/src
          docker stop gitleaks-scan
          docker start -a gitleaks-scan
          docker cp gitleaks-scan:/tmp/gitleaks-results.sarif "${REPORT_DIR}/gitleaks-results.sarif" || true
          docker rm -f gitleaks-scan
        '''
      }
    }

    stage('🧱 Brique 2: SCA (Trivy)') {
      steps {
        sh '''
          docker create --name trivy-scan "${TRIVY_IMAGE}" fs --scanners vuln --format sarif --output /tmp/trivy-results.sarif /src
          docker start trivy-scan
          docker exec trivy-scan sh -c "mkdir -p /src"
          tar --exclude=.git -cf - . | docker cp - trivy-scan:/src
          docker stop trivy-scan
          docker start -a trivy-scan
          docker cp trivy-scan:/tmp/trivy-results.sarif "${REPORT_DIR}/trivy-results.sarif"
          docker rm -f trivy-scan

          # JSON for OPA Gate
          docker run --rm -v "${WORKSPACE}:/src" "${TRIVY_IMAGE}" fs --scanners vuln --format json --output /src/${REPORT_DIR}/trivy-results.json /src
        '''
      }
    }

    stage('🧱 Brique 3 & 4: SAST & SBOM (SonarQube & CycloneDX)') {
      steps {
        sh '''
          docker create --name maven-sec "${MAVEN_IMAGE}" sh -lc "cd /app && mvn -B clean install org.cyclonedx:cyclonedx-maven-plugin:2.9.0:makeBom sonar:sonar -DskipTests -Dsonar.projectKey=${SONAR_PROJECT_KEY} -Dsonar.host.url=${SONAR_URL} -Dsonar.token=${SONAR_TOKEN}"
          docker start maven-sec
          docker exec maven-sec sh -c "mkdir -p /app"
          docker stop maven-sec
          tar --exclude=.git -cf - . | docker cp - maven-sec:/app
          docker start -a maven-sec
          
          # استخراج النتائج
          docker cp maven-sec:/app/target/bom.json "${REPORT_DIR}/bom.json" || true
          docker rm -f maven-sec
        '''
      }
    }

    stage('🧱 Brique 5: DAST (OWASP ZAP)') {
      steps {
        sh '''
          # 1. بناء التطبيق محلياً للتجربة
          docker build -t "${APP_IMAGE}" .
          docker network create "${APP_NETWORK}" || true
          docker run -d --name "${APP_CONTAINER}" --network "${APP_NETWORK}" "${APP_IMAGE}"
          sleep 20 # انتظار اشتغال Spring Boot

          # 2. الهجوم الديناميكي
          docker run --name zap-scan --network "${APP_NETWORK}" -v "${WORKSPACE}/${REPORT_DIR}:/zap/wrk/:rw" "${ZAP_IMAGE}" zap-baseline.py -t "http://${APP_CONTAINER}:8080" -x zap-report.xml -I || true
          
          # 3. تحويل التقرير لـ SARIF
          docker run --rm -v "${WORKSPACE}:/work" python:3.12-alpine sh -lc "python /work/${SCRIPT_DIR}/zap_xml_to_sarif.py /work/${REPORT_DIR}/zap-report.xml /work/${REPORT_DIR}/zap-results.sarif"
          
          # 4. إطفاء التطبيق (لا نحتاجه بعد الآن)
          docker rm -f "${APP_CONTAINER}" zap-scan
          docker network rm "${APP_NETWORK}"
        '''
      }
    }

    stage('🧱 Brique 6: Policy as Code (OPA Gate)') {
      steps {
        sh '''
          docker run --rm -v "${WORKSPACE}:/work" "${OPA_IMAGE}" eval --fail-defined --format pretty --data /work/${POLICY_DIR}/trivy.rego --input /work/${REPORT_DIR}/trivy-results.json "data.trivy.deny" || true
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
        docker rm -f gitleaks-scan trivy-scan maven-sec zap-scan "${APP_CONTAINER}" >/dev/null 2>&1 || true
        docker network rm "${APP_NETWORK}" >/dev/null 2>&1 || true
      '''
    }
    success { echo '✅ Pipeline de Sécurité terminée.' }
    failure { echo '❌ Pipeline de Sécurité en échec.' }
  }
}
