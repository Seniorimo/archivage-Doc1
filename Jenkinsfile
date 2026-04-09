pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  environment {
    APP_IMAGE          = "archivage-doc:${BUILD_NUMBER}"
    APP_CONTAINER      = 'archivage-doc-poc'
    APP_NETWORK        = 'archivage-doc-net'
    DOCKER_NETWORK     = 'devsecops-net'

    MAVEN_IMAGE        = 'maven:3.9.6-eclipse-temurin-17'
    GITLEAKS_IMAGE     = 'zricethezav/gitleaks:v8.21.2'
    TRIVY_IMAGE        = 'aquasec/trivy:latest'
    OPA_IMAGE          = 'openpolicyagent/opa:latest-static'
    ZAP_IMAGE          = 'ghcr.io/zaproxy/zaproxy:stable'

    REPORT_DIR         = 'reports'
    POLICY_DIR         = 'policy'
    SCRIPT_DIR         = 'scripts'
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

    stage('🧱 Brique 1: Gitleaks') {
      steps {
        sh '''
          set -eux
          docker rm -f gitleaks-scan || true
          docker create --name gitleaks-scan "${GITLEAKS_IMAGE}" detect --source=/src --report-format=sarif --report-path=/tmp/gitleaks.sarif --exit-code=0
          docker exec gitleaks-scan mkdir -p /src || true
          tar --exclude=.git -cf - . | docker cp - gitleaks-scan:/src
          docker start -a gitleaks-scan
          docker cp gitleaks-scan:/tmp/gitleaks.sarif "${REPORT_DIR}/gitleaks-results.sarif" || true
          docker rm -f gitleaks-scan
        '''
      }
    }

    stage('🧱 Brique 2: Trivy SCA') {
      steps {
        sh '''
          set -eux
          for fmt in sarif json; do
            docker rm -f trivy-${fmt} || true
            docker create --name trivy-${fmt} "${TRIVY_IMAGE}" fs --scanners vuln --format ${fmt} --output /tmp/trivy.${fmt} /src
            docker exec trivy-${fmt} mkdir -p /src || true
            tar --exclude=.git -cf - . | docker cp - trivy-${fmt}:/src
            docker start -a trivy-${fmt}
            docker cp trivy-${fmt}:/tmp/trivy.${fmt} "${REPORT_DIR}/trivy-results.${fmt}"
            docker rm -f trivy-${fmt}
          done
        '''
      }
    }

    stage('🔨 Maven Build + SBOM') {
      steps {
        sh '''
          set -eux
          docker rm -f maven-build || true
          docker create --name maven-build "${MAVEN_IMAGE}" sh -lc "cd /app && mvn -B clean install org.cyclonedx:cyclonedx-maven-plugin:2.9.0:makeBom -DskipTests"
          tar --exclude=.git -cf - . | docker cp - maven-build:/app
          docker start -a maven-build
          docker cp maven-build:/app/target/bom.json "${REPORT_DIR}/bom.json" || true
          rm -rf target/ && docker cp maven-build:/app/target ./target
          docker rm -f maven-build
        '''
      }
    }

    stage('🧱 SAST SonarQube') {
      steps {
        withSonarQubeEnv('sonarqube') {
          sh '''
            set -eux
            docker rm -f sonar-build || true
            docker create --name sonar-build -e SONAR_HOST_URL=http://sonarqube:9000 -e SONAR_AUTH_TOKEN="${SONAR_AUTH_TOKEN}" "${MAVEN_IMAGE}" sh -lc "cd /app && mvn sonar:sonar -Dsonar.projectKey=archivage-doc"
            tar --exclude=.git --exclude=target -cf - . | docker cp - sonar-build:/app
            docker start -a sonar-build
            docker rm -f sonar-build
          '''
        }
      }
    }

    stage('🐳 Build Docker') {
      steps {
        sh 'docker build -t ${APP_IMAGE} .'
      }
    }

    stage('🧱 DAST ZAP') {
      steps {
        sh '''
          set -eux
          docker network create ${APP_NETWORK} || true
          docker run -d --name ${APP_CONTAINER} --network ${APP_NETWORK} ${APP_IMAGE}
          sleep 25
        '''
        sh '''
          docker run --rm --network ${APP_NETWORK} -v $(pwd)/${REPORT_DIR}:/zap/wrk ${ZAP_IMAGE} \\
            zap-baseline.py -t http://${APP_CONTAINER}:8080 -r /zap/wrk/zap.html -x /zap/wrk/zap.xml || true
        '''
      }
    }

    stage('🛡️ OPA Policy Gate') {
      steps {
        sh '''
          docker run --rm -v $(pwd)/${REPORT_DIR}:/data -v $(pwd)/${POLICY_DIR}:/policy \\
            ${OPA_IMAGE} eval --fail-defined --input /data/trivy-results.json \\
            --data /policy/trivy.rego "data.trivy.deny"
        '''
      }
    }

    stage('📊 Reports') {
      steps {
        recordIssues tools: [
          sarif(pattern: 'reports/*.sarif')
        ]
        archiveArtifacts artifacts: 'reports/**, target/*.jar'
      }
    }
  }

  post {
    always {
      sh '''
        docker rm -f ${APP_CONTAINER} || true
        docker network rm ${APP_NETWORK} || true
      '''
    }
  }
}
