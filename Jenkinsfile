pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
    }

    parameters {
        booleanParam(name: 'ENFORCE_SECURITY_GATE', defaultValue: false, description: 'Strict mode: fail the build if the OPA security gate does not pass')
        booleanParam(name: 'IGNORE_TEST_APP_FINDINGS', defaultValue: false, description: 'Demo mode: ignore findings from /api/test/devsecops/* endpoints')
    }

    environment {
        APP_NAME         = 'archivage-Doc'
        APP_CONTAINER    = 'app-archivage'
        MYSQL_CONTAINER  = 'mysql-archivage'
        NETWORK_NAME     = 'archivage-net'
        APP_PORT         = '8090'
        PROJECT_DIR      = "${WORKSPACE}/src"
        DOCKER_IMAGE     = "archivage-app:${env.BUILD_NUMBER}"
        MAVEN_REPO       = '/var/jenkins_home/.m2/repository'
        TRIVY_CACHE      = "${WORKSPACE}/src/.trivycache"
        SONARQUBE_ENV    = 'sonar'
        SONAR_DOCKER_URL = 'http://host.docker.internal:9000'
        ENFORCE_GATE     = "${params.ENFORCE_SECURITY_GATE}"
        IGNORE_FINDINGS  = "${params.IGNORE_TEST_APP_FINDINGS}"
    }

    stages {
        stage('Init Env') {
            steps {
                script {
                    env.JENKINS_UID = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID = sh(returnStdout: true, script: 'id -g').trim()
                }
            }
        }

        stage('Init & Clean Workspace') {
            steps {
                sh 'docker run --rm -u 0:0 -v "$WORKSPACE:/ws" alpine:3.19 sh -c "find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true; mkdir -p /ws/src; chown -R ${JENKINS_UID}:${JENKINS_GID} /ws"'
                dir('src') { checkout scm }
                sh '''
                    cd "$PROJECT_DIR"
                    rm -rf reports .trivycache .jarpath
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa reports/sonar reports/dashboard .trivycache
                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"
                '''
            }
        }

        stage('Compile & Build Docker Image') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" maven:3.9.9-eclipse-temurin-17 mvn -B -f pom.xml -Dmaven.repo.local="$MAVEN_REPO" clean package -DskipTests
                    find "$PROJECT_DIR/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1 > "$PROJECT_DIR/.jarpath"
                    docker build -t "$DOCKER_IMAGE" .
                '''
            }
        }

        stage('Security Scans') {
            parallel {
                stage('Secrets - Gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                # 1. Raw Scan
                                docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" zricethezav/gitleaks:latest detect --source . --log-opts="--all" --report-format json --report-path reports/gitleaks/gitleaks-raw.json --exit-code 0 || true
                                
                                # 2. Filter findings
                                docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" -e IGNORE_TEST_APP_FINDINGS="$IGNORE_FINDINGS" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/filter_gitleaks.py || true
                                test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
                                
                                # 3. Print Summary
                                docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_gitleaks_summary.py reports/gitleaks/gitleaks-report.json || true
                            '''
                        }
                    }
                }

                stage('SCA - Trivy Image & FS') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                # 1. FS Scan
                                docker run --rm --user 0:0 -v "${TRIVY_CACHE}:/root/.cache/trivy" --volumes-from jenkins -w "$PROJECT_DIR" ghcr.io/aquasecurity/trivy:latest fs --no-progress --quiet --scanners vuln --severity CRITICAL,HIGH,MEDIUM,LOW --format json --output reports/trivy/trivy-fs-report.json . 2> reports/trivy/trivy-fs.stderr.log || true
                                
                                # 2. Image Scan
                                docker run --rm --user 0:0 -v /var/run/docker.sock:/var/run/docker.sock -v "${TRIVY_CACHE}:/root/.cache/trivy" --volumes-from jenkins -w "$PROJECT_DIR" ghcr.io/aquasecurity/trivy:latest image --no-progress --scanners vuln --severity CRITICAL,HIGH,MEDIUM,LOW --format json "$DOCKER_IMAGE" > reports/trivy/trivy-report.json 2> reports/trivy/trivy.stderr.log || true
                                
                                test -s reports/trivy/trivy-report.json || echo '{"Results":[]}' > reports/trivy/trivy-report.json
                                
                                # 3. Print Summary
                                docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_trivy_summary.py reports/trivy/trivy-report.json || true
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            withSonarQubeEnv("${SONARQUBE_ENV}") {
                                sh '''
                                    cd "$PROJECT_DIR"
                                    # 1. Sonar Scanner
                                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --network "$NETWORK_NAME" --volumes-from jenkins --add-host=host.docker.internal:host-gateway -w "$PROJECT_DIR" maven:3.9.9-eclipse-temurin-17 mvn -B -f pom.xml -Dmaven.repo.local="$MAVEN_REPO" org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar -DskipTests -Dsonar.projectKey="$APP_NAME" -Dsonar.host.url="$SONAR_DOCKER_URL" -Dsonar.login="$SONAR_AUTH_TOKEN" -Dsonar.java.binaries="target/classes" -Dsonar.qualitygate.wait=false || true
                                    
                                    # 2. Export API Results
                                    docker run --rm --network "$NETWORK_NAME" --volumes-from jenkins --add-host=host.docker.internal:host-gateway -w "$PROJECT_DIR" curlimages/curl:8.7.1 curl -sf -u "$SONAR_AUTH_TOKEN:" "$SONAR_DOCKER_URL/api/issues/search?componentKeys=$APP_NAME&types=VULNERABILITY&severities=BLOCKER,CRITICAL,MAJOR,MINOR,INFO&p=1&ps=100" -o "reports/sonar/sonar-vulnerabilities.json" || echo '{"issues":[],"total":0}' > "reports/sonar/sonar-vulnerabilities.json"
                                    
                                    # 3. Print Summary
                                    docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_sonar_summary.py reports/sonar/sonar-vulnerabilities.json || true
                                '''
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" maven:3.9.9-eclipse-temurin-17 mvn -B -f pom.xml -Dmaven.repo.local="$MAVEN_REPO" org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all || true
                                cp -f target/bom.xml reports/sbom/bom.xml || true
                                cp -f target/bom.json reports/sbom/bom.json || true
                            '''
                        }
                    }
                }
            }
        }

        stage('Deploy Infrastructure & App') {
            steps {
                sh '''
                    set -eu
                    docker rm -f "$MYSQL_CONTAINER" "$APP_CONTAINER" >/dev/null 2>&1 || true
                    
                    # 1. Deploy MySQL
                    docker run -d --name "$MYSQL_CONTAINER" --network "$NETWORK_NAME" -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=archivage_doc -e MYSQL_USER=archivage_user -e MYSQL_PASSWORD=archivage_pass mysql:8.0 >/dev/null
                    
                    # Wait for MySQL readiness
                    for i in $(seq 1 30); do
                        if docker exec "$MYSQL_CONTAINER" mysqladmin ping -h 127.0.0.1 -uroot -proot --silent >/dev/null 2>&1; then break; fi
                        sleep 3
                    done

                    # 2. Deploy App
                    mkdir -p "$PROJECT_DIR/uploads"
                    docker run -d --name "$APP_CONTAINER" --network "$NETWORK_NAME" --restart on-failure:5 -v "$PROJECT_DIR/uploads:/app/uploads" -e SPRING_PROFILES_ACTIVE=docker -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" -e SPRING_DATASOURCE_USERNAME="archivage_user" -e SPRING_DATASOURCE_PASSWORD="archivage_pass" -e GITHUB_OAUTH_SECRET="test-secret" -e JWT_SECRET="404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970" "$DOCKER_IMAGE" >/dev/null

                    # Wait for App readiness
                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)
                        if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then exit 0; fi
                        sleep 5
                    done
                    docker logs "$APP_CONTAINER" --tail 50
                    exit 1
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        cd "$PROJECT_DIR"
                        mkdir -p reports/zap
                        chmod 777 reports/zap

                        # 1. ZAP Scan (Using dedicated volume for permission safety)
                        ZAP_VOL="zap-reports-$$"
                        docker volume create "$ZAP_VOL" >/dev/null

                        docker run --rm --user root --network "$NETWORK_NAME" -e HOME=/zap -v "${ZAP_VOL}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable bash -c '
                            set -o pipefail
                            umask 0002
                            zap-baseline.py -t "http://app-archivage:8090/" -J zap-report.json -r zap-report.html -a -I 2>&1 | tee /zap/wrk/zap-baseline.log
                            echo ${PIPESTATUS[0]} > /zap/wrk/zap-exit-code.txt
                            chown -R '"${JENKINS_UID}:${JENKINS_GID}"' /zap/wrk || true
                        ' || true

                        # 2. Extract reports from volume
                        docker run --rm --volumes-from jenkins -v "${ZAP_VOL}:/zap/wrk:ro" alpine:3.19 sh -c "cp -f /zap/wrk/* $PROJECT_DIR/reports/zap/ 2>/dev/null || true"
                        docker volume rm "$ZAP_VOL" >/dev/null 2>&1 || true

                        test -s "reports/zap/zap-report.json" || echo '{"site":[{"alerts":[]}]}' > "reports/zap/zap-report.json"
                        
                        # 3. Filter findings
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" -e IGNORE_TEST_APP_FINDINGS="$IGNORE_FINDINGS" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/filter_zap.py || true
                        
                        # 4. Print Summary
                        docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/print_zap_summary.py reports/zap/zap-report.filtered.json || true
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    cd "$PROJECT_DIR"
                    
                    # 1. Build input.json (دابا دوزنا ليه الـ ENFORCE_GATE باش يقراه الكونطينير)
                    docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" -e ENFORCE_GATE="$ENFORCE_GATE" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/build_input.py || true
                    
                    # 2. OPA Eval Debug
                    docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" openpolicyagent/opa:latest eval --format pretty --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security" | tee "reports/opa/opa-debug.txt" || true
                    
                    # 3. OPA Eval Result
                    docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" openpolicyagent/opa:latest eval --format raw --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security.allow" > "reports/opa/opa-result.txt" || true
                    
                    # 4. OPA Thresholds Result
                    docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" openpolicyagent/opa:latest eval --format raw --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security.thresholds_ok" > "reports/opa/opa-thresholds.txt" || true
                '''
                
                script {
                    def allowOk = sh(script: 'cat "$PROJECT_DIR/reports/opa/opa-result.txt" || echo "false"', returnStdout: true).trim()
                    def thresholdsOk = sh(script: 'cat "$PROJECT_DIR/reports/opa/opa-thresholds.txt" || echo "false"', returnStdout: true).trim()
                    
                    // دابا الكلمة الأولى والأخيرة لـ OPA
                    if (allowOk != "true") {
                        error("OPA SECURITY GATE : ECHEC (Strict Mode Activé et Vulnérabilités trouvées)")
                    } else if (thresholdsOk != "true") {
                        unstable("VULNÉRABILITÉS DÉTECTÉES : Build marqué UNSTABLE car les seuils sont dépassés (Strict mode OFF).")
                    } else {
                        echo "OPA SECURITY GATE : PASS (Aucune vulnérabilité critique trouvée)."
                    }
                }
            }
        }

    post {
        always {
            script {
                withSonarQubeEnv("${SONARQUBE_ENV}") {
                    sh '''
                        set +e
                        cd "$PROJECT_DIR"
                        # Generate Custom Security Dashboard
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --network "$NETWORK_NAME" --volumes-from jenkins --add-host=host.docker.internal:host-gateway -e SONAR_HOST_URL="$SONAR_DOCKER_URL" -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" -w "$PROJECT_DIR" python:3.12-alpine python generate_dashboard.py --reports reports --output reports/dashboard/security-dashboard.html --project "$APP_NAME" --sonar-url "$SONAR_DOCKER_URL" --sonar-token "$SONAR_AUTH_TOKEN" --sonar-project "$APP_NAME" || true
                        
                        # Apply CSP patch to HTML report
                        docker run --rm --user "${JENKINS_UID}:${JENKINS_GID}" --volumes-from jenkins -w "$PROJECT_DIR" python:3.12-alpine python ci/scripts/patch_csp.py reports/dashboard/security-dashboard.html || true
                    '''
                }
            }

            sh '''
                set +e
                docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
                docker run --rm -u 0:0 -v "$WORKSPACE:/ws" alpine:3.19 sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null || true"
            '''

            script {
                // Publish HTML Reports
                if (fileExists('src/reports/zap/zap-report.html')) {
                    publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'src/reports/zap', reportFiles: 'zap-report.html', reportName: 'ZAP Web Report'])
                }
                if (fileExists('src/reports/dashboard/security-dashboard.html')) {
                    publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'src/reports/dashboard', reportFiles: 'security-dashboard.html', reportName: 'Security Dashboard'])
                }
                
                // Archive Security Artifacts
                if (fileExists('src/reports')) {
                    archiveArtifacts(
                        artifacts: [
                            'src/reports/gitleaks/gitleaks-raw.json',
                            'src/reports/gitleaks/gitleaks-report.json',
                            'src/reports/trivy/trivy-report.json',
                            'src/reports/trivy/trivy.stderr.log',
                            'src/reports/trivy/trivy-fs-report.json',
                            'src/reports/trivy/trivy-fs.stderr.log',
                            'src/reports/zap/zap-baseline.log',
                            'src/reports/zap/zap-exit-code.txt',
                            'src/reports/zap/zap-report.html',
                            'src/reports/zap/zap-report.json',
                            'src/reports/zap/zap-report.filtered.json',
                            'src/reports/opa/opa-result.txt',
                            'src/reports/opa/opa-debug.txt',
                            'src/reports/opa/opa-thresholds.txt',
                            'src/reports/opa/input.json',
                            'src/reports/sbom/bom.json',
                            'src/reports/sbom/bom.xml',
                            'src/reports/dashboard/security-dashboard.html'
                        ].join(','),
                        allowEmptyArchive: true,
                        fingerprint      : false
                    )
                }
            }
        }

        failure { echo 'Pipeline FAILED - Please check the scan logs and reports.' }
        unstable { echo 'Pipeline UNSTABLE - Security thresholds exceeded. Review the generated reports.' }
        success { echo 'Pipeline SUCCESS - All security gates passed successfully.' }
    }
}