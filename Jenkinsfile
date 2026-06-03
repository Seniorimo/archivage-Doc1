pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
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
        JENKINS_UID      = sh(returnStdout: true, script: 'id -u').trim()
        JENKINS_GID      = sh(returnStdout: true, script: 'id -g').trim()
    }

    stages {

        stage('Force Clean Workspace') {
            steps {
                sh '''
                    set -eux
                    echo "=== FORCE CLEAN WORKSPACE ==="
                    docker run --rm -u 0:0 -v "$WORKSPACE:/ws" alpine:3.19 sh -c "
                        find /ws -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
                        mkdir -p /ws/src
                        chown -R ${JENKINS_UID}:${JENKINS_GID} /ws
                    "
                '''
            }
        }

        stage('Checkout') {
            steps {
                dir('src') {
                    deleteDir()
                    checkout scm
                }
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== PREPARE WORKSPACE ==="
                    rm -rf reports .trivycache .jarpath
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa reports/sonar .trivycache
                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"
                '''
            }
        }

        stage('Compile (Maven)') {
            agent {
                docker {
                    image 'maven:3.9.9-eclipse-temurin-17'
                    args "--user ${env.JENKINS_UID}:${env.JENKINS_GID} --volumes-from jenkins"
                    reuseNode true
                }
            }
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== COMPILATION MAVEN ==="
                    mvn -B -f "$PROJECT_DIR/pom.xml" -Dmaven.repo.local="$MAVEN_REPO" clean package -DskipTests
                    
                    JARPATH=$(find "$PROJECT_DIR/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    echo "$JARPATH" > "$PROJECT_DIR/.jarpath"
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== BUILD DOCKER IMAGE ==="
                    docker build -t "$DOCKER_IMAGE" "$PROJECT_DIR"
                '''
            }
        }

        stage('Security Scans') {
            parallel {

                stage('Secrets - Gitleaks') {
                    agent {
                        docker {
                            image 'zricethezav/gitleaks:latest'
                            args "--volumes-from jenkins"
                            reuseNode true
                        }
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                gitleaks detect --source . --log-opts="--all" --report-format json --report-path reports/gitleaks/gitleaks-report.json --exit-code 0
                                test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
                            '''
                            // Appel direct Python sans docker run
                            sh 'python3 "$PROJECT_DIR/ci/scripts/print_gitleaks_summary.py" "$PROJECT_DIR/reports/gitleaks/gitleaks-report.json"'
                        }
                    }
                }

                stage('SCA - Trivy FS Scan') {
                    agent {
                        docker {
                            image 'ghcr.io/aquasecurity/trivy:latest'
                            args "--user 0:0 -v ${env.TRIVY_CACHE}:/root/.cache/trivy --volumes-from jenkins"
                            reuseNode true
                        }
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                trivy fs --no-progress --quiet --scanners vuln --severity CRITICAL,HIGH --format json --output reports/trivy/trivy-report.json .
                                test -s reports/trivy/trivy-report.json || echo '{"Results":[]}' > reports/trivy/trivy-report.json
                            '''
                            sh 'python3 "$PROJECT_DIR/ci/scripts/print_trivy_summary.py" "$PROJECT_DIR/reports/trivy/trivy-report.json"'
                        }
                    }
                }

                stage('SAST - SonarQube') {
                    agent {
                        docker {
                            image 'maven:3.9.9-eclipse-temurin-17'
                            args "--user ${env.JENKINS_UID}:${env.JENKINS_GID} --network ${env.NETWORK_NAME} --volumes-from jenkins --add-host=host.docker.internal:host-gateway"
                            reuseNode true
                        }
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            withSonarQubeEnv("${SONARQUBE_ENV}") {
                                sh '''
                                    cd "$PROJECT_DIR"
                                    mvn -B -f "$PROJECT_DIR/pom.xml" -Dmaven.repo.local="$MAVEN_REPO" \
                                        org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                        -DskipTests \
                                        -Dsonar.projectKey="$APP_NAME" \
                                        -Dsonar.host.url="$SONAR_DOCKER_URL" \
                                        -Dsonar.login="$SONAR_AUTH_TOKEN" \
                                        -Dsonar.java.binaries="target/classes" \
                                        -Dsonar.qualitygate.wait=false
                                '''
                                sh '''
                                    curl -sf -u "$SONAR_AUTH_TOKEN:" "$SONAR_DOCKER_URL/api/issues/search?componentKeys=$APP_NAME&types=VULNERABILITY&severities=BLOCKER,CRITICAL,MAJOR,MINOR,INFO&p=1&ps=100" -o "$PROJECT_DIR/reports/sonar/sonar-vulnerabilities.json" || echo '{"issues":[],"total":0}' > "$PROJECT_DIR/reports/sonar/sonar-vulnerabilities.json"
                                '''
                                sh 'python3 "$PROJECT_DIR/ci/scripts/print_sonar_summary.py" "$PROJECT_DIR/reports/sonar/sonar-vulnerabilities.json"'
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    agent {
                        docker {
                            image 'maven:3.9.9-eclipse-temurin-17'
                            args "--user ${env.JENKINS_UID}:${env.JENKINS_GID} --volumes-from jenkins"
                            reuseNode true
                        }
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                cd "$PROJECT_DIR"
                                mvn -B -f "$PROJECT_DIR/pom.xml" -Dmaven.repo.local="$MAVEN_REPO" org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all
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

                    # Deploy MySQL
                    docker run -d --name "$MYSQL_CONTAINER" --network "$NETWORK_NAME" -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=archivage_doc -e MYSQL_USER=archivage_user -e MYSQL_PASSWORD=archivage_pass mysql:8.0 >/dev/null
                    sleep 15 # Pause optimisée

                    # Deploy App
                    mkdir -p "$PROJECT_DIR/uploads"
                    docker run -d --name "$APP_CONTAINER" --network "$NETWORK_NAME" --restart on-failure:5 -v "$PROJECT_DIR/uploads:/app/uploads" -e SPRING_PROFILES_ACTIVE=docker -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" -e SPRING_DATASOURCE_USERNAME="archivage_user" -e SPRING_DATASOURCE_PASSWORD="archivage_pass" -e GITHUB_OAUTH_SECRET="test-secret" -e JWT_SECRET="404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970" "$DOCKER_IMAGE" >/dev/null

                    # Healthcheck
                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)
                        if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then
                            echo "Application prete !"
                            exit 0
                        fi
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

                        docker run --rm --user root --network "$NETWORK_NAME" -v "$PROJECT_DIR/reports/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "http://$APP_CONTAINER:$APP_PORT/" -J "zap-report.json" -a -j -I || true
                        docker run --rm -u 0:0 -v "$PROJECT_DIR/reports/zap:/zap/wrk" alpine:3.19 sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /zap/wrk || true"
                        
                        test -s "$PROJECT_DIR/reports/zap/zap-report.json" || echo '{"site":[{"alerts":[]}]}' > "$PROJECT_DIR/reports/zap/zap-report.json"
                    '''
                    // Appel direct Python sans docker run
                    sh 'python3 "$PROJECT_DIR/ci/scripts/zap_to_html.py"'
                    sh 'python3 "$PROJECT_DIR/ci/scripts/print_zap_summary.py" "$PROJECT_DIR/reports/zap/zap-report.json"'
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    cd "$PROJECT_DIR"
                    
                    # Génération de l'input avec Python direct
                    python3 "$PROJECT_DIR/ci/scripts/build_input.py"
                    
                    # Évaluation OPA
                    docker run --rm --volumes-from jenkins -w "$PROJECT_DIR" openpolicyagent/opa:latest eval --format raw --data "ci/policy/security-gate.rego" --input "reports/opa/input.json" "data.security.allow" | tee "reports/opa/opa-result.txt"

                    if ! grep -qx "true" "reports/opa/opa-result.txt"; then
                        echo "OPA SECURITY GATE : ECHEC"
                        exit 1
                    fi
                '''
            }
        }
    }

    post {
        always {
            sh '''
                set +e
                docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
                docker run --rm -u 0:0 -v "$WORKSPACE:/ws" alpine:3.19 sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null || true"
            '''

            script {
                if (fileExists('src/reports/trivy/trivy-report.json')) {
                    recordIssues enabledForFailure: true, aggregatingResults: true, tools: [trivy(pattern: 'src/reports/trivy/trivy-report.json', reportEncoding: 'UTF-8')]
                }
            }

            script {
                if (fileExists('src/reports/zap/zap-report.html')) {
                    publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'src/reports/zap', reportFiles: 'zap-report.html', reportName: 'ZAP Web Report'])
                }
                if (fileExists('src/reports')) {
                    archiveArtifacts artifacts: 'src/reports/**/*', allowEmptyArchive: true, fingerprint: true
                }
            }
        }

        failure { echo 'Pipeline FAILED - consulter les logs de scan.' }
        unstable { echo 'Pipeline UNSTABLE - problemes de securite detectes.' }
        success { echo 'Pipeline SUCCESS - tous les security gates sont passes.' }
    }
}
