pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  environment {
    APP_NAME           = 'archivage-doc'
    APP_IMAGE          = "archivage-doc:${BUILD_NUMBER}"
    APP_CONTAINER      = 'archivage-doc-poc'
    APP_NETWORK        = 'archivage-doc-net'
    
    // RÉSEAU FIXÉ ✅
    DOCKER_NETWORK     = 'devsecops-net'

    MAVEN_IMAGE        = 'maven:3.9.6-eclipse-temurin-17'
    GITLEAKS_IMAGE     = 'zricethezav/gitleaks:v8.21.2'
    TRIVY_IMAGE        = 'aquasec/trivy:latest'
    OPA_IMAGE          = 'openpolicyagent/opa:latest-static'
    ZAP_IMAGE          = 'ghcr.io/zaproxy/zaproxy:stable'

    REPORT_DIR         = 'reports'
    POLICY_DIR         = 'policy'
    SCRIPT_DIR         = 'scripts'

    SONARQUBE_SERVER   = 'sonarqube'
    SONAR_PROJECT_KEY  = 'archivage-doc'
    SONAR_PROJECT_NAME = 'archivage-doc'
  }

  stages {
    stage('📥 Checkout') {
      steps {
        checkout scm
        sh '''
          set -eux
          mkdir -p "${REPORT_DIR}" "${POLICY_DIR}" "${SCRIPT_DIR}"
        '''
      }
    }

    stage('🧱 Brique 1: Secret Detection - Gitleaks') {
      steps {
        sh '''
          set -eux
          docker rm -f gitleaks-scan >/dev/null 2>&1 || true
          docker create --name gitleaks-scan --network ${DOCKER_NETWORK} "${GITLEAKS_IMAGE}" \\
            detect --source=/src --report-format sarif --report-path /tmp/gitleaks.sarif --exit-code 0
          docker exec gitleaks-scan mkdir -p /src
          tar --exclude=.git --exclude="${REPORT_DIR}" --exclude="${POLICY_DIR}" --exclude="${SCRIPT_DIR}" -cf - . | docker cp - gitleaks-scan:/src
          docker start -a gitleaks-scan
          docker cp gitleaks-scan:/tmp/gitleaks.sarif "${REPORT_DIR}/gitleaks-results.sarif" || true
          docker rm -f gitleaks-scan
        '''
      }
    }

    stage('🧱 Brique 2: SCA - Trivy') {
      steps {
        sh '''
          set -eux
          docker rm -f trivy-sarif >/dev/null 2>&1 || true
          docker rm -f trivy-json >/dev/null 2>&1 || true
          
          # SARIF
          docker create --name trivy-sarif --network ${DOCKER_NETWORK} "${TRIVY_IMAGE}" \\
            fs --scanners vuln --format sarif --output /tmp/trivy.sarif /src
          docker exec trivy-sarif mkdir -p /src
          tar --exclude=.git --exclude="${REPORT_DIR}" --exclude="${POLICY_DIR}" --exclude="${SCRIPT_DIR}" -cf - . | docker cp - trivy-sarif:/src
          docker start -a trivy-sarif
          docker cp trivy-sarif:/tmp/trivy.sarif "${REPORT_DIR}/trivy-results.sarif"
          docker rm -f trivy-sarif
          
          # JSON pour OPA
          docker create --name trivy-json --network ${DOCKER_NETWORK} "${TRIVY_IMAGE}" \\
            fs --scanners vuln --format json --output /tmp/trivy.json /src
          docker exec trivy-json mkdir -p /src
          tar --exclude=.git --exclude="${REPORT_DIR}" --exclude="${POLICY_DIR}" --exclude="${SCRIPT_DIR}" -cf - . | docker cp - trivy-json:/src
          docker start -a trivy-json
          docker cp trivy-json:/tmp/trivy.json "${REPORT_DIR}/trivy-results.json"
          docker rm -f trivy-json
        '''
      }
    }

    stage('🧱 Brique 3: Build Maven + SBOM') {
      steps {
        sh '''
          set -eux
          docker rm -f maven-build >/dev/null 2>&1 || true
          docker create --name maven-build --network ${DOCKER_NETWORK} "${MAVEN_IMAGE}" \\
            sh -lc "cd /app && mvn -B clean install org.cyclonedx:cyclonedx-maven-plugin:2.9.0:makeBom -DskipTests"
          tar --exclude=.git --exclude="${REPORT_DIR}" --exclude="${POLICY_DIR}" --exclude="${SCRIPT_DIR}" -cf - . | docker cp - maven-build:/app
          docker start -a maven-build
          docker cp maven-build:/app/target/bom.xml "${REPORT_DIR}/bom.xml" || true
          docker cp maven-build:/app/target/bom.json "${REPORT_DIR}/bom.json" || true
          rm -rf target
          docker cp maven-build:/app/target ./target
          docker rm -f maven-build
        '''
      }
    }

    stage('🧱 Brique 4: SAST - SonarQube') {
      steps {
        withSonarQubeEnv("${SONARQUBE_SERVER}") {
          sh '''
            set -eux
            docker rm -f sonar-build >/dev/null 2>&1 || true
            docker create --name sonar-build --network ${DOCKER_NETWORK} \\
              -e SONAR_HOST_URL=http://${SONARQUBE_SERVER}:9000 \\
              -e SONAR_AUTH_TOKEN="${SONAR_AUTH_TOKEN}" \\
              "${MAVEN_IMAGE}" \\
              sh -lc "cd /app && mvn -B verify sonar:sonar -DskipTests \\
                -Dsonar.projectKey=${SONAR_PROJECT_KEY} \\
                -Dsonar.projectName='${SONAR_PROJECT_NAME}' \\
                -Dsonar.host.url=http://${SONARQUBE_SERVER}:9000 \\
                -Dsonar.token=${SONAR_AUTH_TOKEN}"
            tar --exclude=.git --exclude=.scannerwork --exclude=target --exclude="${REPORT_DIR}" --exclude="${POLICY_DIR}" --exclude="${SCRIPT_DIR}" -cf - . | docker cp - sonar-build:/app
            docker start -a sonar-build
            docker rm -f sonar-build
          '''
        }
      }
    }

    stage('🧱 Brique 5: Build & Run App') {
      steps {
        sh '''
          set -eux
          docker build -t "${APP_IMAGE}" .
        '''
      }
    }

    stage('🧱 Brique 6: DAST - OWASP ZAP') {
      steps {
        sh '''
          set -eux
          docker rm -f "${APP_CONTAINER}" >/dev/null 2>&1 || true
          docker network rm "${APP_NETWORK}" >/dev/null 2>&1 || true
          docker network create "${APP_NETWORK}"
          docker run -d --name "${APP_CONTAINER}" --network "${APP_NETWORK}" "${APP_IMAGE}"
          echo "⏳ Waiting for app startup..."
          sleep 25
          docker logs "${APP_CONTAINER}" --tail 20
        '''
        sh '''
          set -eux
          docker rm -f zap-scan >/dev/null 2>&1 || true
          docker create --name zap-scan --network "${APP_NETWORK}" \\
            -v $(pwd)/${REPORT_DIR}:/zap/wrk/:rw \\
            "${ZAP_IMAGE}" \\
            zap-baseline.py -t "http://${APP_CONTAINER}:8080" -r /zap/wrk/report.html -x /zap/wrk/report.xml || true
          docker start -a zap-scan || true
          docker rm -f zap-scan || true
        '''
        sh '''
          set -eux
          docker rm -f zap-convert >/dev/null 2>&1 || true
          docker create --name zap-convert --network ${DOCKER_NETWORK} python:3.12-alpine \\
            sh -lc "python /work/scripts/zap_xml_to_sarif.py /work/reports/report.xml /work/reports/zap-results.sarif"
          docker cp "${SCRIPT_DIR}/zap_xml_to_sarif.py" zap-convert:/work/scripts/
          docker cp "${REPORT_DIR}/report.xml" zap-convert:/work/reports/ || true
          docker start -a zap-convert || true
          docker cp zap-convert:/work/reports/zap-results.sarif "${REPORT_DIR}/" || true
          docker rm -f zap-convert
        '''
      }
    }

    stage('🧱 Brique 7: Policy Gate - OPA') {
      steps {
        sh '''
          set -eux
          docker rm -f opa-eval >/dev/null 2>&1 || true
          docker create --name opa-eval --network ${DOCKER_NETWORK} "${OPA_IMAGE}" \\
            eval --fail-defined --format pretty --data /work/policy/trivy.rego \\
            --input /work/reports/trivy-results.json "data.trivy.deny"
          docker cp "${POLICY_DIR}/trivy.rego" opa-eval:/work/policy/
          docker cp "${REPORT_DIR}/trivy-results.json" opa-eval:/work/reports/
          docker start -a opa-eval
          docker rm -f opa-eval
        '''
      }
    }

    stage('📊 Publish Reports') {
      steps {
        recordIssues enabledForFailure: true, tools: [
          sarif(id: 'trivy', name: 'Trivy SCA', pattern: 'reports/trivy-results.sarif'),
          sarif(id: 'gitleaks', name: 'Gitleaks Secrets', pattern: 'reports/gitleaks-results.sarif'),
          sarif(id: 'zap', name: 'OWASP ZAP', pattern: 'reports/zap-results.sarif')
        ]
        archiveArtifacts artifacts: 'reports/**/*, target/*.jar', allowEmptyArchive: true
        publishHTML([
          allowMissing: false,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'reports/',
          reportFiles: 'index.html',
          reportName: 'DevSecOps Reports'
        ])
      }
    }
  }

  post {
    always {
      sh '''
        docker rm -f "${APP_CONTAINER}" >/dev/null 2>&1 || true
        docker network rm "${APP_NETWORK}" >/dev/null 2>&1 || true
        docker rm -f maven-build cyclonedx-build sonar-build gitleaks-scan trivy-sarif \\
          trivy-json zap-scan zap-convert opa-eval >/dev/null 2>&1 || true
      '''
    }
    success {
      echo '✅ DevSecOps Pipeline terminée avec succès !'
    }
    failure {
      echo '❌ DevSecOps Pipeline en échec - Vérifiez les logs !'
    }
  }
}
