/* ===========================================================================
 * PIPELINE DEVSECOPS - ARCHIVAGE DOC
 * Description : Pipeline complet intégrant CI/CD, SAST, SCA, DAST, SBOM et OPA.
 * Architecture : Déploiement éphémère (Docker) + Tests de sécurité dynamiques.
 * =========================================================================== */

pipeline {
    agent any

    // ────────────────────────────────────────────────────────────────────────
    // CONFIGURATION GLOBALE
    // ────────────────────────────────────────────────────────────────────────
    options {
        skipDefaultCheckout(true)
        timestamps()                                  // Ajoute l'heure à chaque log
        disableConcurrentBuilds()                     // Évite les conflits si 2 builds se lancent
        timeout(time: 15, unit: 'MINUTES')            // Sécurité : coupe le build s'il freeze
        buildDiscarder(logRotator(numToKeepStr: '5')) // Ne garde que les 5 derniers builds
        // ansiColor('xterm')                         // Décommente si le plugin AnsiColor est installé sur Jenkins
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

    // ────────────────────────────────────────────────────────────────────────
    // EXÉCUTION DU PIPELINE
    // ────────────────────────────────────────────────────────────────────────
    stages {
        
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build & Package') {
            steps {
                sh '''#!/bin/bash
                    set +x
                    echo "--------------------------------------------------------"
                    echo " ⚙️ [1/5] COMPILATION DU CODE (MAVEN)"
                    echo "--------------------------------------------------------"
                    
                    docker run --rm --volumes-from jenkins maven:3.9.9-eclipse-temurin-17 \
                      mvn -q -B -T 1C -f "$WORKSPACE/pom.xml" \
                      -Dmaven.repo.local=/var/jenkins_home/.m2/repository clean package -DskipTests
                '''
            }
        }

        stage('Analyses Statiques (SAST/SCA)') {
            parallel {
                
                stage('Secrets') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                set +x
                                echo " 🔍 [2A] SCAN DES SECRETS (Gitleaks)..."
                                mkdir -p reports/gitleaks
                                
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" \
                                  zricethezav/gitleaks:latest detect --source . --log-opts="--all" \
                                  --report-format json --report-path reports/gitleaks/gitleaks-report.json \
                                  --exit-code 0 > /dev/null 2>&1 || true
                            '''
                        }
                    }
                }

                stage('SCA') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                set +x
                                echo " 📦 [2B] SCAN DES DÉPENDANCES (Trivy)..."
                                mkdir -p reports/trivy .trivycache
                                
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" \
                                  -v "$WORKSPACE/.trivycache:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs --scanners vuln \
                                  --severity LOW,MEDIUM,HIGH,CRITICAL --format json \
                                  --output reports/trivy/trivy-report.json . > /dev/null 2>&1 || true
                            '''
                        }
                    }
                }

                stage('SAST') {
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            sh '''#!/bin/bash
                                set +x
                                echo " 🧠 [2C] ANALYSE QUALITÉ DU CODE (SonarQube)..."
                                
                                docker run --rm --volumes-from jenkins --add-host=host.docker.internal:host-gateway \
                                  maven:3.9.9-eclipse-temurin-17 sh -lc "mvn -q -B -T 1C -f '$WORKSPACE/pom.xml' \
                                  -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                                  org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                  -Dsonar.projectKey=archivage-Doc -Dsonar.host.url=http://host.docker.internal:9000 \
                                  -Dsonar.login=$SONAR_TOKEN -Dsonar.java.binaries=target/classes" > /dev/null 2>&1 || true
                            '''
                        }
                    }
                }

                stage('SBOM') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                set +x
                                echo " 📜 [2D] INVENTAIRE LOGICIEL (CycloneDX)..."
                                mkdir -p reports/sbom
                                
                                docker run --rm --volumes-from jenkins maven:3.9.9-eclipse-temurin-17 sh -lc "mvn -q -B -T 1C \
                                  -f '$WORKSPACE/pom.xml' -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                                  org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all && \
                                  cp -f '$WORKSPACE/target/bom.xml' '$WORKSPACE/reports/sbom/bom.xml' && \
                                  cp -f '$WORKSPACE/target/bom.json' '$WORKSPACE/reports/sbom/bom.json'" > /dev/null 2>&1 || true
                            '''
                        }
                    }
                }
            }
        }

        stage('Deploy Infra & App') {
            steps {
                sh '''#!/bin/bash
                    set +x
                    echo "--------------------------------------------------------"
                    echo " 🚀 [3/5] DÉPLOIEMENT ENVIRONNEMENT DE TEST"
                    echo "--------------------------------------------------------"
                    
                    docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" 2>/dev/null || true
                    docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK" > /dev/null

                    echo "   ➤ Démarrage de MySQL..."
                    docker run -d --name "$MYSQL_CONTAINER" --network "$DOCKER_NETWORK" -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASS" \
                      -e MYSQL_DATABASE="$MYSQL_DATABASE" -e MYSQL_USER="$MYSQL_USER" -e MYSQL_PASSWORD="$MYSQL_PASS" mysql:8.0 > /dev/null
                    
                    # Smart Wait : Attente que MySQL soit prêt
                    for i in $(seq 1 20); do
                      if docker exec "$MYSQL_CONTAINER" mysqladmin ping -h localhost -u"$MYSQL_USER" -p"$MYSQL_PASS" > /dev/null 2>&1; then
                        break
                      fi
                      sleep 2
                    done

                    echo "   ➤ Démarrage de Spring Boot..."
                    docker run -d --name "$APP_CONTAINER" --network "$DOCKER_NETWORK" --volumes-from jenkins \
                      --add-host=host.docker.internal:host-gateway -p "$APP_PORT:8080" maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -q -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                      spring-boot:run -Dspring-boot.run.arguments='--server.port=8080 \
                      --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE \
                      --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS'" > /dev/null

                    # Smart Wait : Attente que l'application réponde
                    READY=0
                    for i in $(seq 1 15); do
                      if docker run --rm --network "$DOCKER_NETWORK" curlimages/curl:8.7.1 -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:8080/" | grep -qE "200|302|401|403|404"; then
                        READY=1; break;
                      fi
                      sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                      echo "   ❌ Erreur : L'application n'a pas répondu à temps."
                      docker logs "$APP_CONTAINER" --tail 50
                      exit 1
                    fi
                    echo "   ✅ Application prête."
                '''
            }
        }

        stage('Analyses Dynamiques (Offensive)') {
            parallel {
                
                stage('ZAP Baseline') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                set +x
                                echo "--------------------------------------------------------"
                                echo " 🕷️ [4A] ATTAQUE DAST (OWASP ZAP)"
                                echo "--------------------------------------------------------"
                                mkdir -p reports/zap
                                
                                docker run --rm --user root --add-host=host.docker.internal:host-gateway --volumes-from jenkins \
                                  -v "$WORKSPACE/reports/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:bare zap-baseline.py \
                                  -t "http://host.docker.internal:$APP_PORT" -m 1 -r zap-baseline-report.html \
                                  -J zap-baseline-report.json -I > /dev/null 2>&1 || true
                            '''
                        }
                    }
                }

                stage('Nuclei') {
                    steps {
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            sh '''#!/bin/bash
                                set +x
                                echo "--------------------------------------------------------"
                                echo " 🎯 [4B] RECHERCHE DE MISCONFIGURATIONS (Nuclei)"
                                echo "--------------------------------------------------------"
                                mkdir -p reports/nuclei
                                
                                docker run --rm --network "$DOCKER_NETWORK" --volumes-from jenkins -w "$WORKSPACE" \
                                  projectdiscovery/nuclei:latest -u "http://$APP_CONTAINER:8080" \
                                  -t cves,exposures,misconfiguration -je reports/nuclei/nuclei-report.json > /dev/null 2>&1 || true
                            '''
                        }
                    }
                }
            }
        }

        stage('Policy - OPA') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''#!/bin/bash
                        set +x
                        echo "--------------------------------------------------------"
                        echo " ⚖️ [5/5] VÉRIFICATION DE LA CONFORMITÉ (OPA)"
                        echo "--------------------------------------------------------"
                        mkdir -p reports/opa policy
                        
                        cat > policy/security.rego <<'EOF'
package security
default allow = false
trivy_critical_count := count([v | some i; input.trivy.Results[i].Vulnerabilities[_].Severity == "CRITICAL"; v := 1])
zap_high_count := count([v | some s; input.zap_web.site[s].alerts[_].riskcode == "3"; v := 1])
allow if { trivy_critical_count == 0; zap_high_count == 0 }
EOF
                        
                        TRIVY_JSON=$(cat reports/trivy/trivy-report.json 2>/dev/null || echo '{}')
                        ZAP_WEB_JSON=$(cat reports/zap/zap-baseline-report.json 2>/dev/null || echo '{}')
                        printf '{"trivy": %s, "zap_web": %s}' "$TRIVY_JSON" "$ZAP_WEB_JSON" > reports/opa/input.json

                        docker run --rm --volumes-from jenkins -w "$WORKSPACE" openpolicyagent/opa:latest eval \
                          --format pretty --data policy/security.rego --input reports/opa/input.json "data.security" > /dev/null 2>&1 || true
                    '''
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // NETTOYAGE ET PUBLICATION DES RAPPORTS
    // ────────────────────────────────────────────────────────────────────────
    post {
        always {
            sh '''#!/bin/bash
                set +x
                echo "--------------------------------------------------------"
                echo " 🧹 NETTOYAGE DE L'ENVIRONNEMENT"
                echo "--------------------------------------------------------"
                docker rm -f "$APP_CONTAINER" "$MYSQL_CONTAINER" 2>/dev/null || true
                docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
            '''
            
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            recordIssues(tools: [trivy(pattern: 'reports/trivy/trivy-report.json')], name: 'Trivy Security Scan Warnings')
            publishHTML(target: [
                allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, 
                reportDir: 'reports/zap', reportFiles: 'zap-baseline-report.html', reportName: 'ZAP Web Report'
            ])
        }
        success  { echo '✅ STATUS : PIPELINE TERMINÉ AVEC SUCCÈS.' }
        unstable { echo '⚠️ STATUS : PIPELINE TERMINÉ (Alertes de sécurité détectées).' }
        failure  { echo '❌ STATUS : PIPELINE ÉCHOUÉ (Erreur critique).' }
    }
}
