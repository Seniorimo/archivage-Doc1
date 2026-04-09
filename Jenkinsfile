pipeline {
  agent any

  tools {
    jdk 'JDK17'
    maven 'Maven3'
  }

  options {
    timestamps()
    ansiColor('xterm')
    disableConcurrentBuilds()
  }

  environment {
    SONARQUBE_SERVER = 'SonarQubeServer'
    ARTIFACT_PATTERN = 'target/*.jar, target/*.war'
    IMAGE_NAME = 'archivage-doc'
    CONTAINER_NAME = 'archivage-doc-smoke'
    APP_PORT = '8090'
    HOST_PORT = '18081'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Build') {
      steps {
        sh 'mvn -B clean install -DskipTests'
      }
    }

    stage('SCA - Dependency Check') {
      steps {
        withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_API_KEY')]) {
          sh '''
            mvn -B org.owasp:dependency-check-maven:check \
              -DnvdApiKey=$NVD_API_KEY \
              -Dformat=HTML \
              -DoutputDirectory=target/dependency-check-report \
              -DfailBuildOnCVSS=9
          '''
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'target/dependency-check-report/**', allowEmptyArchive: true
        }
      }
    }

    stage('SAST - SonarQube') {
      steps {
        withSonarQubeEnv("${SONARQUBE_SERVER}") {
          sh 'mvn -B sonar:sonar'
        }
      }
    }

    stage('Archive') {
      steps {
        archiveArtifacts artifacts: "${ARTIFACT_PATTERN}", fingerprint: true
      }
    }

    stage('Prepare Docker Metadata') {
      steps {
        script {
          env.GIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
          env.LOCAL_IMAGE = "${IMAGE_NAME}:build-${BUILD_NUMBER}"
          env.VERSION_TAG = "${BUILD_NUMBER}-${GIT_SHORT}"
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        sh '''
          docker build --no-cache -t "$LOCAL_IMAGE" .
        '''
      }
    }

    stage('Smoke Test Docker') {
      steps {
        sh '''
          docker rm -f "$CONTAINER_NAME" || true

          docker run -d \
            --name "$CONTAINER_NAME" \
            -p "$HOST_PORT:$APP_PORT" \
            -e SPRING_PROFILES_ACTIVE=docker \
            "$LOCAL_IMAGE"

          sleep 30

          docker logs "$CONTAINER_NAME" --tail 300

          docker logs "$CONTAINER_NAME" | grep "Started ArchivageDocApplication"
        '''
      }
    }

    stage('Push Docker Image') {
      steps {
        withCredentials([usernamePassword(
          credentialsId: 'dockerhub-credentials',
          usernameVariable: 'DOCKERHUB_USER',
          passwordVariable: 'DOCKERHUB_PASS'
        )]) {
          sh '''
            REPO="$DOCKERHUB_USER/$IMAGE_NAME"
            VERSION_IMAGE="$REPO:$VERSION_TAG"
            LATEST_IMAGE="$REPO:latest"

            echo "$DOCKERHUB_PASS" | docker login -u "$DOCKERHUB_USER" --password-stdin

            docker tag "$LOCAL_IMAGE" "$VERSION_IMAGE"
            docker tag "$LOCAL_IMAGE" "$LATEST_IMAGE"

            docker push "$VERSION_IMAGE"
            docker push "$LATEST_IMAGE"

            docker logout || true
          '''
        }
      }
    }
  }

  post {
    success {
      echo 'SUCCESS: Build + SCA + SAST + Archive + Docker build + smoke test + push terminés correctement.'
    }

    failure {
      echo 'FAILURE: la pipeline CI/CD a échoué. Vérifiez les logs des stages pour identifier la cause.'
    }

    always {
      sh 'docker rm -f "$CONTAINER_NAME" || true'
      echo "Pipeline terminée - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
    }
  }
}