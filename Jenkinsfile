pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 60, unit: 'MINUTES')
        skipDefaultCheckout(false)
    }

    environment {
        REPORTS_DIR       = "${WORKSPACE}/reports"

        GITLEAKS_DIR      = "${WORKSPACE}/reports/gitleaks"
        TRIVY_DIR         = "${WORKSPACE}/reports/trivy"
        SBOM_DIR          = "${WORKSPACE}/reports/sbom"
        SONAR_DIR         = "${WORKSPACE}/reports/sonar"
        ZAP_DIR           = "${WORKSPACE}/reports/zap"
        OPA_DIR           = "${WORKSPACE}/reports/opa"

        SONAR_HOST_URL    = "http://localhost:9000"
        SONAR_PROJECT_KEY = "archivage-doc"

        // Remplace par ton URL de staging si l'application est déjà déployée
        ZAP_TARGET_URL    = "http://host.docker.internal:8081"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

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

                    if [ ! -d "${WORKSPACE}/.git" ]; then
                      echo "ERROR: .git directory not found in workspace"
                      exit 1
                    fi

                    git rev-parse --is-inside-work-tree

                    # Important pour éviter certains problèmes de shallow clone
                    git fetch --unshallow || true
                    git fetch --tags --prune || true

                    # Vérification rapide
                    git status --short || true
                '''
            }
        }

        stage('Security Scans') {
            parallel {

                stage('Secrets - Gitleaks') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                sh '''
                                    set +e

                                    rm -f "${GITLEAKS_DIR}/gitleaks.json"

                                    docker run --rm \
                                      --user "$(id -u):$(id -g)" \
                                      -v "${WORKSPACE}:/repo:ro" \
                                      -v "${GITLEAKS_DIR}:/out:rw" \
                                      ghcr.io/gitleaks/gitleaks:latest detect \
                                      --source /repo \
                                      --report-format json \
                                      --report-path /out/gitleaks.json \
                                      --exit-code 0 \
                                      --redact

                                    if [ ! -f "${GITLEAKS_DIR}/gitleaks.json" ]; then
                                      echo "Git mode failed, fallback to filesystem scan (--no-git)"
                                      docker run --rm \
                                        --user "$(id -u):$(id -g)" \
                                        -v "${WORKSPACE}:/repo:ro" \
                                        -v "${GITLEAKS_DIR}:/out:rw" \
                                        ghcr.io/gitleaks/gitleaks:latest detect \
                                        --no-git \
                                        --source /repo \
                                        --report-format json \
                                        --report-path /out/gitleaks.json \
                                        --exit-code 0 \
                                        --redact
                                    fi

                                    if [ ! -f "${GITLEAKS_DIR}/gitleaks.json" ]; then
                                      echo '{"status":"error","message":"gitleaks report not generated"}' > "${GITLEAKS_DIR}/gitleaks.json"
                                      exit 1
                                    fi
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

                                    rm -f "${TRIVY_DIR}/trivy-fs.json"

                                    docker run --rm \
                                      --user "$(id -u):$(id -g)" \
                                      -v "${WORKSPACE}:/src:ro" \
                                      -v "${TRIVY_DIR}:/out:rw" \
                                      ghcr.io/aquasecurity/trivy:latest fs \
                                      --scanners vuln \
                                      --format json \
                                      --output /out/trivy-fs.json \
                                      /src

                                    if [ ! -f "${TRIVY_DIR}/trivy-fs.json" ]; then
                                      echo '{"status":"error","message":"trivy report not generated"}' > "${TRIVY_DIR}/trivy-fs.json"
                                      exit 1
                                    fi
                                '''
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                sh '''
                                    set +e

                                    rm -f "${SBOM_DIR}/bom.json"

                                    if [ -f "${WORKSPACE}/pom.xml" ]; then
                                      mvn -B -f "${WORKSPACE}/pom.xml" \
                                        org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom \
                                        -DoutputFormat=json \
                                        -DoutputDirectory="${SBOM_DIR}" \
                                        -DoutputName=bom
                                    else
                                      echo '{"status":"skipped","message":"pom.xml not found"}' > "${SBOM_DIR}/bom.json"
                                    fi

                                    if [ ! -f "${SBOM_DIR}/bom.json" ]; then
                                      echo '{"status":"error","message":"cyclonedx report not generated"}' > "${SBOM_DIR}/bom.json"
                                      exit 1
                                    fi
                                '''
                            }
                        }
                    }
                }

                stage('SAST - SonarQube') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                                    sh '''
                                        set +e

                                        rm -f "${SONAR_DIR}/sonar-status.json"

                                        if [ -f "${WORKSPACE}/pom.xml" ]; then
                                          mvn -B -f "${WORKSPACE}/pom.xml" sonar:sonar \
                                            -Dsonar.projectKey="${SONAR_PROJECT_KEY}" \
                                            -Dsonar.host.url="${SONAR_HOST_URL}" \
                                            -Dsonar.token="${SONAR_TOKEN}"

                                          echo '{"status":"submitted"}' > "${SONAR_DIR}/sonar-status.json"
                                        else
                                          echo '{"status":"skipped","message":"pom.xml not found"}' > "${SONAR_DIR}/sonar-status.json"
                                        fi
                                    '''
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh '''
                            set +e

                            rm -f "${ZAP_DIR}/zap-report.html" "${ZAP_DIR}/zap-report.json"

                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -v "${ZAP_DIR}:/zap/wrk:rw" \
                              --network host \
                              ghcr.io/zaproxy/zaproxy:stable \
                              zap-baseline.py \
                              -t "${ZAP_TARGET_URL}" \
                              -r zap-report.html \
                              -J zap-report.json \
                              -I

                            if [ ! -f "${ZAP_DIR}/zap-report.json" ]; then
                              echo '{"status":"error","message":"zap report not generated"}' > "${ZAP_DIR}/zap-report.json"
                              exit 1
                            fi
                        '''
                    }
                }
            }
        }

        stage('Policy - OPA') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh '''
                            set +e

                            cat > "${OPA_DIR}/policy.rego" <<'EOF'
                            package cicd.security

                            default allow = true

                            deny contains "Missing Trivy report" if {
                              input.trivy_report_exists == false
                            }

                            deny contains "Missing Gitleaks report" if {
                              input.gitleaks_report_exists == false
                            }
                            EOF

                            TRIVY_EXISTS=false
                            GITLEAKS_EXISTS=false

                            [ -f "${TRIVY_DIR}/trivy-fs.json" ] && TRIVY_EXISTS=true
                            [ -f "${GITLEAKS_DIR}/gitleaks.json" ] && GITLEAKS_EXISTS=true

                            cat > "${OPA_DIR}/input.json" <<EOF
                            {
                              "trivy_report_exists": ${TRIVY_EXISTS},
                              "gitleaks_report_exists": ${GITLEAKS_EXISTS}
                            }
                            EOF

                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -v "${OPA_DIR}:/policy:rw" \
                              openpolicyagent/opa:latest \
                              eval \
                              --format json \
                              --data /policy/policy.rego \
                              --input /policy/input.json \
                              "data.cicd.security" > "${OPA_DIR}/opa-result.json"

                            if [ ! -f "${OPA_DIR}/opa-result.json" ]; then
                              echo '{"status":"error","message":"opa result not generated"}' > "${OPA_DIR}/opa-result.json"
                              exit 1
                            fi
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true, fingerprint: true
        }
        unstable {
            echo 'Pipeline terminé avec des erreurs ou findings de sécurité. Vérifie les rapports archivés.'
        }
        success {
            echo 'Pipeline DevSecOps terminé avec succès.'
        }
        failure {
            echo 'Le pipeline a échoué à cause d’une erreur de pipeline ou d’environnement.'
        }
    }
}
