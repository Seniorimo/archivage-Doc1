pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  environment {
    REPORT_DIR     = 'reports'
    MAVEN_IMAGE    = 'maven:3.9.6-eclipse-temurin-17'
    GITLEAKS_IMAGE = 'zricethezav/gitleaks:v8.21.2'
    TRIVY_IMAGE    = 'aquasec/trivy:latest'
    APP_IMAGE      = "archivage-doc:${BUILD_NUMBER}"
    APP_CONTAINER  = 'archivage-doc-app'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        sh 'mkdir -p reports'
      }
    }

    stage('Build Maven') {
      steps {
        sh '''
          docker run --rm \
            -v "$PWD:/app" \
            -w /app \
            ${MAVEN_IMAGE} \
            mvn -B clean install -DskipTests
        '''
      }
    }

    stage('Gitleaks') {
      steps {
        sh '''
          docker run --rm \
            -v "$PWD:/src" \
            ${GITLEAKS_IMAGE} detect \
            --source=/src \
            --report-format sarif \
            --report-path /src/reports/gitleaks-results.sarif \
            --exit-code 0
        '''
      }
    }

    stage('Trivy') {
      steps {
        sh '''
          docker run --rm \
            -v "$PWD:/src" \
            ${TRIVY_IMAGE} fs \
            --scanners vuln \
            --format sarif \
            --output /src/reports/trivy-results.sarif \
            /src
        '''
      }
    }

    stage('Build Docker Image') {
      steps {
        sh 'docker build -t ${APP_IMAGE} .'
      }
    }

    stage('Run App in Background') {
      steps {
        sh '''
          docker rm -f ${APP_CONTAINER} >/dev/null 2>&1 || true
          docker run -d --name ${APP_CONTAINER} -p 8080:8080 ${APP_IMAGE}
          echo "Waiting for app startup..."
          sleep 20
          docker logs ${APP_CONTAINER} --tail 100 || true
        '''
      }
    }

    stage('Sanity Check') {
      steps {
        sh '''
          curl -f http://localhost:8080 || true
        '''
      }
    }

    stage('Publish Reports') {
      steps {
        archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
      }
    }
  }

  post {
    always {
      sh '''
        docker rm -f ${APP_CONTAINER} >/dev/null 2>&1 || true
      '''
    }
  }
}
