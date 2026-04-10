pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds() // Évite les conflits si plusieurs builds se lancent
    }

    environment {
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
            steps {
                checkout scm
            }
        }

        // ─── BUILD CENTRALISÉ ─────────────────────────────────────────────────
        // On compile une seule fois ici. Les briques SAST et SBOM utiliseront ces binaires.
        stage('Build & Package') {
            steps {
                sh '''
                    docker run --rm \
                      --volumes-from jenkins \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B \
                        -f "$WORKSPACE/pom.xml" \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        clean package -DskipTests
                '''
            }
        }

        // ─── EXÉCUTION PARALLÈLE DES SCANS STATIQUES ──────────────────────────
        // Ces 4 briques tournent en même temps pour un gain de performance massif
        stage('Analyses de Sécurité (Static)') {
            parallel {
                
                // ─── BRIQUE 1 : SECRETS (Gitleaks) -> Cible: Code & Git
                stage('Secrets') {
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

                // ─── BRIQUE 2 : SCA (Trivy) -> Cible: Dépendances (pom.xml)
                stage('SCA') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/trivy
                                mkdir -p .trivycache
                                
                                # Génération JSON pour Jenkins/OPA
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" \
                                  -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs --scanners vuln \
                                  --severity LOW,MEDIUM,HIGH,CRITICAL --format json \
                                  --output reports/trivy/trivy-report.json . || true

                                # Génération HTML pour l'archivage
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" \
                                  -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs --scanners vuln \
                                  --severity LOW,MEDIUM,HIGH,CRITICAL --format template \
                                  --template "@contrib/html.tpl" \
                                  --output reports/trivy/trivy-report.html . || true
                            '''
                        }
                    }
                }

                // ─── BRIQUE 3 : SAST (SonarQube) -> Cible: Code source Java
                stage('SAST') {
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''
                                docker run --rm --volumes-from jenkins \
                                  --add-host=host.docker.internal:host-gateway \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  sh -lc "mvn -B -f '$WORKSPACE/pom.xml' \
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

                // ─── BRIQUE 4 : SBOM (CycloneDX) -> Cible: Conformité / Inventaire
                stage('SBOM') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''
                                mkdir -p reports/sbom
                                docker run --rm --volumes-from jenkins \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  sh -lc "mvn -B -f '$WORKSPACE/pom.xml' \
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

        // ─── DÉPLOIEMENT ENVIRONNEMENT DE TEST ────────────────────────────────
        stage('Deploy Infra & App') {
            steps {
                sh '''
                    # Nettoyage préalable
                    docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" 2>/dev/null || true
                    docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK"

                    # Lancement MySQL
                    docker run -d --name "$MYSQL_CONTAINER" --network "$DOCKER_NETWORK" \
                      -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASS" -e MYSQL_DATABASE="$MYSQL_DATABASE" \
                      -e MYSQL_USER="$MYSQL_USER" -e MYSQL_PASSWORD="$MYSQL_PASS" mysql:8.0
                    sleep 20 # Attente raccourcie, MySQL 8.0 met un peu de temps au premier boot

                    # Lancement App
                    docker run -d --name "$APP_CONTAINER" --network "$DOCKER_NETWORK" \
                      --volumes-from jenkins --add-host=host.docker.internal:host-gateway \
                      -p "$APP_PORT:$APP_PORT" maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B -f '$WORKSPACE/pom.xml' \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        spring-boot:run \
                        -Dspring-boot.run.arguments='--server.port=$APP_PORT --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS'"

                    # Healthcheck avec Timeout
                    echo "En attente du démarrage de l'application..."
                    READY=0
                    for i in $(seq 1 10); do
                      if docker run --rm --network "$DOCKER_NETWORK" curlimages/curl:8.7.1 -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/" | grep -qE "200|302|401|403"; then
                        READY=1; break;
                      fi
                      sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                      echo "Échec du démarrage. Logs:"
                      docker logs "$APP_CONTAINER" --tail 100
                      exit 1
                    fi
                '''
            }
        }

        // ─── BRIQUE 5 : DAST (OWASP ZAP) -> Cible: Application Runtime ────────
        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/zap
                        docker run --rm --user root --add-host=host.docker.internal:host-gateway \
                          --volumes-from jenkins -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                          ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                          -t "http://host.docker.internal:$APP_PORT" \
                          -r zap-report.html -J zap-report.json -I || true
                    '''
                }
            }
        }

        // ─── BRIQUE 6 : POLICY (OPA) -> Cible: Résultats des scans ────────────
        stage('Policy - OPA') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p reports/opa policy
                        
                        cat > policy/security.rego <<'EOF'
package security
default allow = false
trivy_critical_count := count([v | some i; input.trivy.Results[i].Vulnerabilities[_].Severity == "CRITICAL"; v := 1])
zap_high_count := count([v | some s; input.zap.site[s].alerts[_].riskcode == "3"; v := 1])
allow if { trivy_critical_count == 0; zap_high_count == 0 }
EOF

                        TRIVY_JSON=$(cat reports/trivy/trivy-report.json 2>/dev/null || echo '{}')
                        ZAP_JSON=$(cat reports/zap/zap-report.json 2>/dev/null || echo '{}')
                        
                        printf '{"trivy": %s, "zap": %s}' "$TRIVY_JSON" "$ZAP_JSON" > reports/opa/input.json

                        docker run --rm --volumes-from jenkins -w "$WORKSPACE" openpolicyagent/opa:latest eval \
                          --format pretty --data policy/security.rego --input reports/opa/input.json "data.security" > reports/opa/opa-result.txt 2>&1 || true
                          
                        echo "=== Résultat OPA ==="
                        cat reports/opa/opa-result.txt || true
                    '''
                }
            }
        }
    }

    // ─── POST ACTIONS : ARCHIVAGE & NETTOYAGE ─────────────────────────────────
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true

            recordIssues(
                tools: [trivy(pattern: 'reports/trivy/trivy-report.json')],
                name: 'Trivy Security Scan Warnings'
            )

            publishHTML(target: [
                allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                reportDir: 'reports/trivy', reportFiles: 'trivy-report.html', reportName: 'Trivy CVE Report'
            ])

            publishHTML(target: [
                allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                reportDir: 'reports/zap', reportFiles: 'zap-report.html', reportName: 'ZAP DAST Report'
            ])

            // Nettoyage systématique de l'environnement de test
            sh '''
                docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" 2>/dev/null || true
                docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
            '''
        }
        success { echo '✅ Pipeline DevSecOps terminé avec succès' }
        unstable { echo '⚠️ Pipeline terminé — certaines alertes de sécurité sont remontées' }
        failure { echo '❌ Pipeline échoué — vérifier les logs' }
    }
}
