pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '15'))
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
    }

    environment {
        APP_NAME          = 'archivage-doc'
        GIT_URL           = 'https://github.com/Seniorimo/archivage-Doc1.git'
        GIT_BRANCH        = '*/main'

        SONARQUBE_SERVER  = 'SonarQube'   // à adapter si besoin
        APP_PORT          = '8080'
        HEALTHCHECK_URL   = 'http://localhost:8080/actuator/health'

        REPORTS_DIR       = 'reports'
        IMAGE_NAME        = "archivage-doc:${BUILD_NUMBER}"
        CONTAINER_NAME    = "archivage-doc-test-${BUILD_NUMBER}"

        PACKAGE_OK        = 'false'
        IMAGE_OK          = 'false'
        DEPLOY_OK         = 'false'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: "${env.GIT_BRANCH}"]],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [],
                    userRemoteConfigs: [[url: "${env.GIT_URL}"]]
                ])

                sh '''
                    echo "--------------------------------------------------------"
                    echo " CHECKOUT OK"
                    echo "--------------------------------------------------------"
                    pwd
                    ls -la
                    test -f pom.xml
                    mkdir -p "${REPORTS_DIR}"/{gitleaks,trivy,trivy-image,sbom,zap,opa}
                    chmod +x mvnw || true
                '''
            }
        }

        stage('Tests Unitaires') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        echo "--------------------------------------------------------"
                        echo " [1/8] TESTS UNITAIRES (JUnit + JaCoCo)"
                        echo "--------------------------------------------------------"
                        ./mvnw -B test jacoco:report
                    '''
                }
            }
            post {
                always {
                    junit testResults: 'target/surefire-reports/*.xml',
                          allowEmptyResults: true,
                          keepLongStdio: true

                    publishHTML(target: [
                        reportName: 'JaCoCo Coverage',
                        reportDir: 'target/site/jacoco',
                        reportFiles: 'index.html',
                        keepAll: true,
                        alwaysLinkToLastBuild: true,
                        allowMissing: true
                    ])

                    archiveArtifacts artifacts: 'target/surefire-reports/**, target/site/jacoco/**',
                                     allowEmptyArchive: true,
                                     fingerprint: true
                }
            }
        }

        stage('Analyses Statiques (SAST/SCA)') {
            failFast false
            parallel {

                stage('Secrets (Gitleaks)') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "--------------------------------------------------------"
                                echo " [2/8] SECRETS SCAN (Gitleaks)"
                                echo "--------------------------------------------------------"
                                gitleaks detect \
                                  --source . \
                                  --report-format json \
                                  --report-path ${REPORTS_DIR}/gitleaks/gitleaks-report.json
                            '''
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/gitleaks/**",
                                             allowEmptyArchive: true,
                                             fingerprint: true
                        }
                    }
                }

                stage('SCA (Trivy FS)') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "--------------------------------------------------------"
                                echo " [3/8] SCA (Trivy FS)"
                                echo "--------------------------------------------------------"
                                trivy fs . \
                                  --scanners vuln,secret,misconfig \
                                  --format json \
                                  --output ${REPORTS_DIR}/trivy/trivy-fs-report.json
                            '''
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/trivy/**",
                                             allowEmptyArchive: true,
                                             fingerprint: true
                        }
                    }
                }

                stage('SAST (SonarQube)') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            withSonarQubeEnv("${SONARQUBE_SERVER}") {
                                sh '''
                                    echo "--------------------------------------------------------"
                                    echo " [4/8] SAST (SonarQube)"
                                    echo "--------------------------------------------------------"
                                    ./mvnw -B -DskipTests sonar:sonar
                                '''
                            }
                        }
                    }
                }

                stage('SBOM (CycloneDX / Syft)') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "--------------------------------------------------------"
                                echo " [5/8] SBOM (CycloneDX / Syft)"
                                echo "--------------------------------------------------------"

                                if command -v syft >/dev/null 2>&1; then
                                  syft . -o cyclonedx-json > ${REPORTS_DIR}/sbom/sbom-cyclonedx.json
                                else
                                  ./mvnw -B -DskipTests org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
                                  if [ -f target/bom.json ]; then
                                    cp target/bom.json ${REPORTS_DIR}/sbom/sbom-cyclonedx.json
                                  elif [ -f target/bom.xml ]; then
                                    cp target/bom.xml ${REPORTS_DIR}/sbom/bom.xml
                                  fi
                                fi
                            '''
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/sbom/**",
                                             allowEmptyArchive: true,
                                             fingerprint: true
                        }
                    }
                }
            }
        }

        stage('SonarQube Quality Gate') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    timeout(time: 10, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: false
                    }
                }
            }
        }

        stage('Build & Package') {
            steps {
                script {
                    try {
                        sh '''
                            echo "--------------------------------------------------------"
                            echo " [6/8] BUILD & PACKAGE"
                            echo "--------------------------------------------------------"
                            ./mvnw -B -DskipTests clean package
                        '''
                        env.PACKAGE_OK = 'true'
                    } catch (err) {
                        env.PACKAGE_OK = 'false'
                        currentBuild.result = 'UNSTABLE'
                        echo "Build & Package en échec : ${err}"
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/*.jar',
                                     allowEmptyArchive: true,
                                     fingerprint: true
                }
            }
        }

        stage('Build Image Docker') {
            when {
                expression { env.PACKAGE_OK == 'true' }
            }
            steps {
                script {
                    try {
                        sh '''
                            echo "--------------------------------------------------------"
                            echo " [7/8] BUILD IMAGE DOCKER"
                            echo "--------------------------------------------------------"
                            docker build -t ${IMAGE_NAME} .
                        '''
                        env.IMAGE_OK = 'true'
                    } catch (err) {
                        env.IMAGE_OK = 'false'
                        currentBuild.result = 'UNSTABLE'
                        echo "Build image Docker en échec : ${err}"
                    }
                }
            }
        }

        stage('Trivy Image Scan') {
            when {
                expression { env.IMAGE_OK == 'true' }
            }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        echo "--------------------------------------------------------"
                        echo " [8/8] TRIVY IMAGE SCAN"
                        echo "--------------------------------------------------------"
                        trivy image \
                          --format json \
                          --output ${REPORTS_DIR}/trivy-image/trivy-image-report.json \
                          ${IMAGE_NAME}
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/trivy-image/**",
                                     allowEmptyArchive: true,
                                     fingerprint: true
                }
            }
        }

        stage('Deploy Test Env') {
            when {
                expression { env.IMAGE_OK == 'true' }
            }
            steps {
                script {
                    try {
                        sh '''
                            echo "--------------------------------------------------------"
                            echo " DEPLOY TEST ENV"
                            echo "--------------------------------------------------------"

                            docker rm -f ${CONTAINER_NAME} || true
                            docker run -d --name ${CONTAINER_NAME} -p ${APP_PORT}:8080 ${IMAGE_NAME}

                            for i in $(seq 1 30); do
                              if curl -fsS ${HEALTHCHECK_URL} >/dev/null 2>&1; then
                                echo "Application disponible"
                                exit 0
                              fi
                              echo "Attente du healthcheck... tentative $i/30"
                              sleep 5
                            done

                            echo "Healthcheck KO"
                            exit 1
                        '''
                        env.DEPLOY_OK = 'true'
                    } catch (err) {
                        env.DEPLOY_OK = 'false'
                        currentBuild.result = 'UNSTABLE'
                        echo "Déploiement test en échec : ${err}"
                    }
                }
            }
        }

        stage('DAST Policy') {
            failFast false
            parallel {

                stage('DAST OWASP ZAP') {
                    when {
                        expression { env.DEPLOY_OK == 'true' }
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "--------------------------------------------------------"
                                echo " DAST OWASP ZAP"
                                echo "--------------------------------------------------------"
                                zap-baseline.py -t http://localhost:${APP_PORT} -r ${REPORTS_DIR}/zap/zap-report.html
                            '''
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/zap/**",
                                             allowEmptyArchive: true,
                                             fingerprint: true
                        }
                    }
                }

                stage('Policy OPA') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "--------------------------------------------------------"
                                echo " POLICY OPA"
                                echo "--------------------------------------------------------"

                                if [ -f ${REPORTS_DIR}/sbom/sbom-cyclonedx.json ]; then
                                  opa eval \
                                    --format pretty \
                                    --data policy \
                                    --input ${REPORTS_DIR}/sbom/sbom-cyclonedx.json \
                                    "data" > ${REPORTS_DIR}/opa/opa-result.txt
                                else
                                  echo "Aucun SBOM disponible pour OPA" > ${REPORTS_DIR}/opa/opa-result.txt
                                fi
                            '''
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/opa/**",
                                             allowEmptyArchive: true,
                                             fingerprint: true
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            sh '''
                echo "--------------------------------------------------------"
                echo " NETTOYAGE"
                echo "--------------------------------------------------------"
                docker rm -f ${CONTAINER_NAME} || true
            '''

            archiveArtifacts artifacts: "${REPORTS_DIR}/**, target/surefire-reports/**, target/site/jacoco/**, target/*.jar",
                             allowEmptyArchive: true,
                             fingerprint: true
        }

        success {
            echo 'PIPELINE TERMINE AVEC SUCCES'
        }

        unstable {
            echo 'PIPELINE TERMINE EN UNSTABLE - verifier les rapports'
        }

        failure {
            echo 'PIPELINE EN ECHEC - verifier les rapports'
        }
    }
}
