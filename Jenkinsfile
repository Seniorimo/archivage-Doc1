pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 60, unit: 'MINUTES')
        skipDefaultCheckout(true)
    }

    parameters {
        string(name: 'ZAP_TARGET_URL', defaultValue: 'http://host.docker.internal:8081', description: 'URL cible pour le scan ZAP')
    }

    environment {
        REPORTS_DIR       = "${WORKSPACE}/reports"
        GITLEAKS_DIR      = "${WORKSPACE}/reports/gitleaks"
        TRIVY_DIR         = "${WORKSPACE}/reports/trivy"
        SBOM_DIR          = "${WORKSPACE}/reports/sbom"
        SONAR_DIR         = "${WORKSPACE}/reports/sonar"
        ZAP_DIR           = "${WORKSPACE}/reports/zap"
        OPA_DIR           = "${WORKSPACE}/reports/opa"

        SONAR_HOST_URL    = "http://host.docker.internal:9000"
        SONAR_PROJECT_KEY = "archivage-doc"
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

                    install -d -m 0755 "${REPORTS_DIR}" \
                                      "${GITLEAKS_DIR}" \
                                      "${TRIVY_DIR}" \
                                      "${SBOM_DIR}" \
                                      "${SONAR_DIR}" \
                                      "${ZAP_DIR}" \
                                      "${OPA_DIR}"

                    test -d "${WORKSPACE}/.git"
                    git rev-parse --is-inside-work-tree

                    git fetch --unshallow || true
                    git fetch --tags --prune || true
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
                                      -u "$(id -u):$(id -g)" \
                                      -e GIT_DISCOVERY_ACROSS_FILESYSTEM=1 \
                                      -w /repo \
                                      -v "${WORKSPACE}:/repo:ro" \
                                      -v "${GITLEAKS_DIR}:/out:rw" \
                                      ghcr.io/gitleaks/gitleaks:latest detect \
                                      --source /repo \
                                      --report-format json \
                                      --report-path /out/gitleaks.json \
                                      --exit-code 0 \
                                      --redact

                                    if [ ! -f "${GITLEAKS_DIR}/gitleaks.json" ]; then
                                      echo "Fallback to --no-git"
                                      docker run --rm \
                                        -u "$(id -u):$(id -g)" \
                                        -w /repo \
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
                                      -u "$(id -u):$(id -g)" \
                                      -e TRIVY_CACHE_DIR=/tmp/trivycache \
                                      -w /src \
                                      -v "${WORKSPACE}:/src:ro" \
                                      -v "${TRIVY_DIR}:/out:rw" \
                                      ghcr.io/aquasecurity/trivy:latest fs \
                                      --scanners vuln \
                                      --format json \
                                      --output /out/trivy-fs.json \
                                      /src

                                    ls -lah "${TRIVY_DIR}" || true

                                    if [ ! -f "${TRIVY_DIR}/trivy-fs.json" ]; then
                                      echo '{"status":"skipped","message":"trivy report not generated or no supported manifests found"}' > "${TRIVY_DIR}/trivy-fs.json"
                                      exit 0
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
                                      docker run --rm \
                                        -u "$(id -u):$(id -g)" \
                                        -v "${WORKSPACE}:/workspace" \
                                        -v "${WORKSPACE}/.m2:/var/maven/.m2" \
                                        -w /workspace \
                                        maven:3.9.9-eclipse-temurin-17 \
                                        mvn -B -Dmaven.repo.local=/var/maven/.m2/repository \
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
                                          docker run --rm \
                                            -u "$(id -u):$(id -g)" \
                                            --add-host=host.docker.internal:host-gateway \
                                            -v "${WORKSPACE}:/workspace" \
                                            -v "${WORKSPACE}/.m2:/var/maven/.m2" \
                                            -w /workspace \
                                            maven:3.9.9-eclipse-temurin-17 \
                                            mvn -B -Dmaven.repo.local=/var/maven/.m2/repository \
                                            sonar:sonar \
                                            -Dsonar.projectKey="${SONAR_PROJECT_KEY}" \
                                            -Dsonar.host.url="${SONAR_HOST_URL}" \
                                            -Dsonar.token="${SONAR_TOKEN}"

                                          rc=$?
                                          if [ $rc -eq 0 ]; then
                                            echo '{"status":"submitted"}' > "${SONAR_DIR}/sonar-status.json"
                                          else
                                            echo '{"status":"error","message":"sonar scan failed"}' > "${SONAR_DIR}/sonar-status.json"
                                            exit 1
                                          fi
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
                              --add-host=host.docker.internal:host-gateway \
                              curlimages/curl:8.7.1 \
                              -s -o /dev/null -w "%{http_code}" "${ZAP_TARGET_URL}" > "${ZAP_DIR}/target-status.txt" 2>/dev/null

                            HTTP_CODE=$(cat "${ZAP_DIR}/target-status.txt" 2>/dev/null || echo "000")

                            if [ -z "${HTTP_CODE}" ] || [ "${HTTP_CODE}" = "000" ]; then
                              echo '{"status":"skipped","message":"target unreachable for ZAP"}' > "${ZAP_DIR}/zap-report.json"
                              exit 0
                            fi

                            docker run --rm \
                              -u "$(id -u):$(id -g)" \
                              --add-host=host.docker.internal:host-gateway \
                              -v "${ZAP_DIR}:/zap/wrk:rw" \
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

                            deny contains "Missing Gitleaks report" if {
                              input.gitleaks_report_exists == false
                            }

                            deny contains "Missing Trivy report" if {
                              input.trivy_report_exists == false
                            }

                            deny contains "Missing SBOM report" if {
                              input.sbom_report_exists == false
                            }
                            EOF

                            GITLEAKS_EXISTS=false
                            TRIVY_EXISTS=false
                            SBOM_EXISTS=false
                            SONAR_EXISTS=false
                            ZAP_EXISTS=false

                            [ -f "${GITLEAKS_DIR}/gitleaks.json" ] && GITLEAKS_EXISTS=true
                            [ -f "${TRIVY_DIR}/trivy-fs.json" ] && TRIVY_EXISTS=true
                            [ -f "${SBOM_DIR}/bom.json" ] && SBOM_EXISTS=true
                            [ -f "${SONAR_DIR}/sonar-status.json" ] && SONAR_EXISTS=true
                            [ -f "${ZAP_DIR}/zap-report.json" ] && ZAP_EXISTS=true

                            cat > "${OPA_DIR}/input.json" <<EOF
                            {
                              "gitleaks_report_exists": ${GITLEAKS_EXISTS},
                              "trivy_report_exists": ${TRIVY_EXISTS},
                              "sbom_report_exists": ${SBOM_EXISTS},
                              "sonar_report_exists": ${SONAR_EXISTS},
                              "zap_report_exists": ${ZAP_EXISTS}
                            }
                            EOF

                            docker run --rm \
                              -u "$(id -u):$(id -g)" \
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
            echo 'Pipeline terminé en UNSTABLE. Vérifie les rapports archivés dans reports/.'
        }
        success {
            echo 'Pipeline DevSecOps terminé avec succès.'
        }
        failure {
            echo 'Le pipeline a échoué à cause d’une erreur d’infrastructure ou de script.'
        }
    }
}
