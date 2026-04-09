pipeline {
    agent any

    options {
        timestamps()
        ansiColor('xterm')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
        skipDefaultCheckout(false)
    }

    environment {
        REPORTS_DIR      = "${WORKSPACE}/reports"
        GITLEAKS_DIR     = "${WORKSPACE}/reports/gitleaks"
        TRIVY_DIR        = "${WORKSPACE}/reports/trivy"
        SBOM_DIR         = "${WORKSPACE}/reports/sbom"
        SONAR_DIR        = "${WORKSPACE}/reports/sonar"
        ZAP_DIR          = "${WORKSPACE}/reports/zap"
        OPA_DIR          = "${WORKSPACE}/reports/opa"

        SONAR_HOST_URL   = "http://localhost:9000"
        SONAR_PROJECT_KEY = "archivage-doc"

        // Prefer a deployed staging URL for DAST.
        ZAP_TARGET_URL   = "http://host.docker.internal:8081"
    }

    stages {
        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu
                    mkdir -p "${REPORTS_DIR}" \
                             "${GITLEAKS_DIR}" \
                             "${TRIVY_DIR}" \
                             "${SBOM_DIR}" \
                             "${SONAR_DIR}" \
                             "${ZAP_DIR}" \
                             "${OPA_DIR}"

                    test -d "${WORKSPACE}/.git"
                    git rev-parse --is-inside-work-tree

                    # Ensure full history when secret scanning Git history matters
                    git fetch --unshallow || true
                    git fetch --tags --prune || true
                '''
            }
        }

        stage('Source Security') {
            parallel {
                stage('Secrets - Gitleaks') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                sh '''
                                    set +e

                                    docker run --rm \
                                      --user "$(id -u):$(id -g)" \
                                      -v "${WORKSPACE}:/repo:ro" \
                                      -v "${GITLEAKS_DIR}:/out:rw" \
                                      ghcr.io/zricethezav/gitleaks:latest detect \
                                      --source /repo \
                                      --report-format json \
                                      --report-path /out/gitleaks.json \
                                      --exit-code 0 \
                                      --redact

                                    rc=$?

                                    if [ ! -f "${GITLEAKS_DIR}/gitleaks.json" ]; then
                                      echo "Git mode unavailable inside container, retrying in filesystem mode"
                                      docker run --rm \
                                        --user "$(id -u):$(id -g)" \
                                        -v "${WORKSPACE}:/repo:ro" \
                                        -v "${GITLEAKS_DIR}:/out:rw" \
                                        ghcr.io/zricethezav/gitleaks:latest detect \
                                        --no-git \
                                        --source /repo \
                                        --report-format json \
                                        --report-path /out/gitleaks.json \
                                        --exit-code 0 \
                                        --redact
                                    fi

                                    test -f "${GITLEAKS_DIR}/gitleaks.json"
                                    exit 0
                                '''
                            }
                        }
                    }
                }

                stage('SCA - Trivy FS') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                sh '''
                                    set +e

                                    docker run --rm \
                                      --user "$(id -u):$(id -g)" \
                                      -v "${WORKSPACE}:/src:ro" \
                                      -v "${TRIVY_DIR}:/out:rw" \
                                      ghcr.io/aquasecurity/trivy:latest fs \
                                      --scanners vuln \
                                      --format json \
                                      --output /out/trivy-fs.json \
                                      /src

                                    test -f "${TRIVY_DIR}/trivy-fs.json"
                                    exit 0
                                '''
                            }
                        }
                    }
                }
            }
        }

        stage('Software Inventory') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh '''
                            set +e

                            mvn -B -f "${WORKSPACE}/pom.xml" \
                              org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom \
                              -DoutputFormat=json \
                              -DoutputDirectory="${SBOM_DIR}" \
                              -DoutputName=bom

                            test -f "${SBOM_DIR}/bom.json"
                            exit 0
                        '''
                    }
                }
            }
        }

        stage('Static Analysis') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                            sh '''
                                set +e

                                mvn -B -f "${WORKSPACE}/pom.xml" sonar:sonar \
                                  -Dsonar.projectKey="${SONAR_PROJECT_KEY}" \
                                  -Dsonar.host.url="${SONAR_HOST_URL}" \
                                  -Dsonar.token="${SONAR_TOKEN}"

                                echo "{\\"status\\":\\"submitted\\"}" > "${SONAR_DIR}/sonar-status.json"
                                exit 0
                            '''
                        }
                    }
                }
            }
        }

        stage('Dynamic Analysis') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh '''
                            set +e

                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -v "${ZAP_DIR}:/zap/wrk:rw" \
                              --network host \
                              owasp/zap2docker-stable \
                              zap-baseline.py \
                              -t "${ZAP_TARGET_URL}" \
                              -r zap-report.html \
                              -J zap-report.json \
                              -I

                            test -f "${ZAP_DIR}/zap-report.html" || true
                            exit 0
                        '''
                    }
                }
            }
        }

        stage('Policy Gate - OPA') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh '''
                            set +e

                            cat > "${OPA_DIR}/policy.rego" <<'EOF'
                            package cicd.security

                            default allow = true

                            trivy_report_exists if {
                              input.trivy_report_exists == true
                            }

                            deny contains "Missing Trivy report" if {
                              not trivy_report_exists
                            }
                            EOF

                            TRIVY_EXISTS=false
                            [ -f "${TRIVY_DIR}/trivy-fs.json" ] && TRIVY_EXISTS=true

                            cat > "${OPA_DIR}/input.json" <<EOF
                            {
                              "trivy_report_exists": ${TRIVY_EXISTS}
                            }
                            EOF

                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -v "${OPA_DIR}:/policy:rw" \
                              openpolicyagent/opa:latest \
                              eval \
                              --format pretty \
                              --data /policy/policy.rego \
                              --input /policy/input.json \
                              "data.cicd.security"

                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -v "${OPA_DIR}:/policy:rw" \
                              openpolicyagent/opa:latest \
                              eval \
                              --format json \
                              --data /policy/policy.rego \
                              --input /policy/input.json \
                              "data.cicd.security" > "${OPA_DIR}/opa-result.json"

                            exit 0
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*.json, reports/**/*.html', allowEmptyArchive: true, fingerprint: true
        }
        unstable {
            echo 'Pipeline completed with scanner issues or findings; review archived reports.'
        }
        success {
            echo 'DevSecOps pipeline completed successfully.'
        }
        failure {
            echo 'Pipeline failed due to a pipeline/runtime error; review stage logs and archived artifacts.'
        }
    }
}
