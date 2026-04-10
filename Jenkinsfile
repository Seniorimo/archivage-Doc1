pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 15, unit: 'MINUTES') // Sécurité anti-freeze
        buildDiscarder(logRotator(numToKeepStr: '5')) // Évite de saturer l'espace disque de Jenkins
    }

    environment {
        // 🛠️ CORRECTION ICI : On expose l'application sur le port 8081 vers l'extérieur
        // pour ne pas entrer en conflit avec le port 8080 de Jenkins lui-même.
        APP_PORT        = '8081' 
        MYSQL_ROOT_PASS = 'root'
        MYSQL_DATABASE  = 'archivage_db'
        MYSQL_USER      = 'archivage_user'
        MYSQL_PASS      = 'archivage_pass'
        DOCKER_NETWORK  = 'archivage-net'
        MYSQL_CONTAINER = 'mysql-archivage'
        APP_CONTAINER   = 'app-archivage'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        // ─── COMPILATION MULTITHREAD ──────────────────────────────────────────
        stage('Build & Package') {
            steps {
                sh '''
                    docker run --rm --volumes-from jenkins \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B -T 1C -f "$WORKSPACE/pom.xml" \
                      -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                      clean package -DskipTests
                '''
            }
        }

        // ─── ANALYSES STATIQUES EN PARALLÈLE ──────────────────────────────────
        stage('Analyses Statiques (SAST/SCA)') {
            parallel {
                stage('Secrets (Gitleaks)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/gitleaks
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" \
                                  zricethezav/gitleaks:latest detect --source . \
                                  --log-opts="--all" --report-format json \
                                  --report-path reports/gitleaks/gitleaks-report.json --exit-code 0 || true
                            '''
                        }
                    }
                }

                stage('SCA (Trivy)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/trivy .trivycache
                                # Uniquement la génération JSON pour Jenkins, évite les freezes
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" \
                                  -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs --scanners vuln \
                                  --severity LOW,MEDIUM,HIGH,CRITICAL --format json \
                                  --output reports/trivy/trivy-report.json . || true
                            '''
                        }
                    }
                }

                stage('SAST (SonarQube)') {
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''
                                docker run --rm --volumes-from jenkins \
                                  --add-host=host.docker.internal:host-gateway \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  sh -lc "mvn -B -T 1C -f '$WORKSPACE/pom.xml' \
                                    -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                                    org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                    -Dsonar.projectKey=archivage-Doc \
                                    -Dsonar.host.url=http://host.docker.internal:9000 \
                                    -Dsonar.login=$SONAR_TOKEN \
                                    -Dsonar.java.binaries=target/classes"
                            '''
                        }
                    }
                }

                stage('SBOM (CycloneDX)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/sbom
                                docker run --rm --volumes-from jenkins maven:3.9.9-eclipse-temurin-17 \
                                  sh -lc "mvn -B -T 1C -f '$WORKSPACE/pom.xml' \
                                    -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                                    org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                                    -DoutputFormat=all && \
                                    cp -f '$WORKSPACE/target/bom.xml' '$WORKSPACE/reports/sbom/bom.xml' && \
                                    cp -f '$WORKSPACE/target/bom.json' '$WORKSPACE/reports/sbom/bom.json'" || true
                            '''
                        }
                    }
                }
            }
        }

        // ─── DÉPLOIEMENT DE L'INFRASTRUCTURE DE TEST ──────────────────────────
        stage('Deploy Infra & App') {
            steps {
                sh '''
                    docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" 2>/dev/null || true
                    docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK"

                    docker run -d --name "$MYSQL_CONTAINER" --network "$DOCKER_NETWORK" \
                      -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASS" -e MYSQL_DATABASE="$MYSQL_DATABASE" \
                      -e MYSQL_USER="$MYSQL_USER" -e MYSQL_PASSWORD="$MYSQL_PASS" mysql:8.0
                    sleep 10 

                    # 🛠️ CORRECTION DU PORT ICI : On lie le port externe 8081 vers le 8080 interne
                    docker run -d --name "$APP_CONTAINER" --network "$DOCKER_NETWORK" \
                      --volumes-from jenkins --add-host=host.docker.internal:host-gateway \
                      -p "$APP_PORT:8080" maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B -f '$WORKSPACE/pom.xml' \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        spring-boot:run \
                        -Dspring-boot.run.arguments='--server.port=8080 --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS'"

                    echo "Attente du démarrage..."
                    READY=0
                    for i in $(seq 1 12); do
                      # Le Healthcheck attaque le port 8080 car il est lancé DEPUIS le réseau Docker
                      if docker run --rm --network "$DOCKER_NETWORK" curlimages/curl:8.7.1 -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:8080/" | grep -qE "200|302|401|403|404"; then
                        READY=1; break;
                      fi
                      sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                      echo "Échec du démarrage."
                      docker logs "$APP_CONTAINER" --tail 100
                      exit 1
                    fi
                '''
            }
        }

        // ─── ANALYSES DYNAMIQUES EN PARALLÈLE ─────────────────────────────────
        stage('Analyses Dynamiques (Offensive)') {
            parallel {
                stage('ZAP Baseline (Web)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/zap
                                # ZAP attaque le port externe (8081) depuis Jenkins
                                docker run --rm --user root --add-host=host.docker.internal:host-gateway \
                                  --volumes-from jenkins -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                                  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                                  -t "http://host.docker.internal:$APP_PORT" \
                                  -m 1 \
                                  -r zap-baseline-report.html -J zap-baseline-report.json -I || true
                            '''
                        }
                    }
                }

                stage('Nuclei (Misconfigs)') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/nuclei
                                # Nuclei attaque le port interne (8080) car il tourne dans le réseau Docker
                                docker run --rm --network "$DOCKER_NETWORK" \
                                  --volumes-from jenkins -w "$WORKSPACE" \
                                  projectdiscovery/nuclei:latest \
                                  -u "http://$APP_CONTAINER:8080" \
                                  -t cves,exposures,misconfiguration,vulnerabilities \
                                  -je reports/nuclei/nuclei-report.json || true
                            '''
                        }
                    }
                }
            }
        }

        // ─── GOUVERNANCE OPA ──────────────────────────────────────────────────
        stage('Policy - OPA') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/opa policy
                        cat > policy/security.rego <<'EOF'
package security
default allow = false
trivy_critical_count := count([v | some i; input.trivy.Results[i].Vulnerabilities[_].Severity == "CRITICAL"; v := 1])
zap_high_count := count([v | some s; input.zap_web.site[s].alerts[_].riskcode == "3"; v := 1])
nuclei_critical_count := count([v | some i; input.nuclei[i].info.severity == "critical"; v := 1])
allow if { trivy_critical_count == 0; zap_high_count == 0; nuclei_critical_count == 0 }
EOF
                        TRIVY_JSON=$(cat reports/trivy/trivy-report.json 2>/dev/null || echo '{}')
                        ZAP_WEB_JSON=$(cat reports/zap/zap-baseline-report.json 2>/dev/null || echo '{}')
                        NUCLEI_JSON=$(cat reports/nuclei/nuclei-report.json 2>/dev/null || echo '[]')
                        
                        printf '{"trivy": %s, "zap_web": %s, "nuclei": %s}' "$TRIVY_JSON" "$ZAP_WEB_JSON" "$NUCLEI_JSON" > reports/opa/input.json

                        docker run --rm --volumes-from jenkins -w "$WORKSPACE" openpolicyagent/opa:latest eval \
                          --format pretty --data policy/security.rego --input reports/opa/input.json "data.security" > reports/opa/opa-result.txt 2>&1 || true
                    '''
                }
            }
        }
    }

    // ─── NETTOYAGE ET RAPPORTS ──────────────────────────────────────────────
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true

            recordIssues(
                tools: [trivy(pattern: 'reports/trivy/trivy-report.json')],
                name: 'Trivy Security Scan Warnings'
            )

            publishHTML(target: [
                allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                reportDir: 'reports/zap', reportFiles: 'zap-baseline-report.html', reportName: 'ZAP Web Report'
            ])

            sh '''
                docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" 2>/dev/null || true
                docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
            '''
        }
        success { echo '✅ Pipeline DevSecOps terminé avec succès' }
        unstable { echo '⚠️ Pipeline terminé — Alertes de sécurité détectées (non bloquantes)' }
        failure { echo '❌ Pipeline échoué' }
    }
}
