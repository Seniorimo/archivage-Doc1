pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
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
        WORKSPACE_DIR   = '/var/jenkins_home/workspace/DevSecOps-PFE-Test'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Gitleaks Secrets Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p $WORKSPACE_DIR/reports/gitleaks

                        docker run --rm \
                          --volumes-from jenkins \
                          -w $WORKSPACE_DIR \
                          zricethezav/gitleaks:latest \
                          detect \
                          --source . \
                          --log-opts="--all" \
                          --report-format json \
                          --report-path reports/gitleaks/gitleaks-report.json \
                          --exit-code 0 || true
                    '''
                }
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    docker run --rm \
                      --volumes-from jenkins \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B \
                        -f $WORKSPACE_DIR/pom.xml \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        clean package -DskipTests
                '''
            }
        }

        stage('Trivy SCA Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p $WORKSPACE_DIR/reports/trivy

                        docker run --rm \
                          --volumes-from jenkins \
                          aquasec/trivy:latest fs \
                          --scanners vuln \
                          --format json \
                          --output $WORKSPACE_DIR/reports/trivy/trivy-fs-report.json \
                          $WORKSPACE_DIR || true
                    '''
                }
            }
        }

        stage('CycloneDX SBOM') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p $WORKSPACE_DIR/reports/sbom

                        docker run --rm \
                          --volumes-from jenkins \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "
                            mvn -B \
                              -f $WORKSPACE_DIR/pom.xml \
                              -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                              org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                              -DoutputFormat=all &&
                            cp -f $WORKSPACE_DIR/target/bom.xml  $WORKSPACE_DIR/reports/sbom/bom.xml &&
                            cp -f $WORKSPACE_DIR/target/bom.json $WORKSPACE_DIR/reports/sbom/bom.json
                          " || true
                    '''
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        docker run --rm \
                          --volumes-from jenkins \
                          --add-host=host.docker.internal:host-gateway \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "
                            mvn -B \
                              -f $WORKSPACE_DIR/pom.xml \
                              -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                              clean compile \
                              org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                              -Dsonar.projectKey=archivage-Doc \
                              -Dsonar.host.url=http://host.docker.internal:9000 \
                              -Dsonar.login=$SONAR_TOKEN \
                              -Dsonar.java.binaries=target/classes
                          "
                    '''
                }
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    docker rm -f $MYSQL_CONTAINER 2>/dev/null || true
                    docker network inspect $DOCKER_NETWORK >/dev/null 2>&1 || docker network create $DOCKER_NETWORK

                    docker run -d \
                      --name $MYSQL_CONTAINER \
                      --network $DOCKER_NETWORK \
                      -e MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASS \
                      -e MYSQL_DATABASE=$MYSQL_DATABASE \
                      -e MYSQL_USER=$MYSQL_USER \
                      -e MYSQL_PASSWORD=$MYSQL_PASS \
                      mysql:8.0

                    echo "Waiting for MySQL..."
                    sleep 25
                    docker logs $MYSQL_CONTAINER --tail 20 || true
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    docker rm -f $APP_CONTAINER 2>/dev/null || true

                    docker run -d \
                      --name $APP_CONTAINER \
                      --network $DOCKER_NETWORK \
                      --volumes-from jenkins \
                      --add-host=host.docker.internal:host-gateway \
                      -p $APP_PORT:$APP_PORT \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B \
                        -f $WORKSPACE_DIR/pom.xml \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        spring-boot:run \
                        -Dspring-boot.run.arguments='--server.port=$APP_PORT --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS'"

                    echo "Waiting for Spring Boot..."
                    sleep 10

                    READY=0
                    for i in $(seq 1 12); do
                      STATUS=$(docker run --rm \
                        --network $DOCKER_NETWORK \
                        curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" \
                        http://$APP_CONTAINER:$APP_PORT/ || true)

                      echo "Attempt $i/12 -> HTTP status: $STATUS"

                      if echo "$STATUS" | grep -qE "200|302"; then
                        READY=1
                        break
                      fi

                      sleep 10
                    done

                    if [ "$READY" -ne 1 ]; then
                      echo "Application did not become ready. Container logs:"
                      docker logs $APP_CONTAINER --tail 200 || true
                      exit 1
                    fi
                '''
            }
        }

        stage('ZAP DAST Scan') {
            steps {
                sh '''
                    mkdir -p $WORKSPACE_DIR/reports/zap

                    docker run --rm \
                      --user root \
                      --add-host=host.docker.internal:host-gateway \
                      --volumes-from jenkins \
                      -v $WORKSPACE_DIR/reports/zap:/zap/wrk:rw \
                      ghcr.io/zaproxy/zaproxy:stable \
                      zap-baseline.py \
                      -t http://host.docker.internal:$APP_PORT \
                      -r zap-report.html \
                      -J zap-report.json \
                      -I
                '''
            }
        }

        stage('OPA Policy Check') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p $WORKSPACE_DIR/reports/opa

                        GITLEAKS_COUNT=$(grep -o '"RuleID"' "$WORKSPACE_DIR/reports/gitleaks/gitleaks-report.json" | wc -l || true)
                        TRIVY_CRITICAL=$(grep -o 'CRITICAL' "$WORKSPACE_DIR/reports/trivy/trivy-fs-report.json" | wc -l || true)
                        ZAP_HIGH=$(grep -o '"riskcode":"3"' "$WORKSPACE_DIR/reports/zap/zap-report.json" | wc -l || true)

                        cat > $WORKSPACE_DIR/reports/opa/policy-input.json <<EOF
{
  "gitleaks_findings": $GITLEAKS_COUNT,
  "trivy_critical": $TRIVY_CRITICAL,
  "zap_high": $ZAP_HIGH
}
EOF

                        cat > $WORKSPACE_DIR/reports/opa/policy.rego <<'EOF'
package cicd

default allow = true

deny[msg] {
  input.gitleaks_findings > 0
  msg := sprintf("Gitleaks found %v potential secret(s)", [input.gitleaks_findings])
}

deny[msg] {
  input.trivy_critical > 0
  msg := sprintf("Trivy found %v CRITICAL finding(s)", [input.trivy_critical])
}

deny[msg] {
  input.zap_high > 0
  msg := sprintf("ZAP found %v High-risk alert(s)", [input.zap_high])
}

allow {
  count(deny) == 0
}
EOF

                        docker run --rm \
                          --volumes-from jenkins \
                          openpolicyagent/opa:latest \
                          eval \
                          --format pretty \
                          --data $WORKSPACE_DIR/reports/opa/policy.rego \
                          --input $WORKSPACE_DIR/reports/opa/policy-input.json \
                          'data.cicd' | tee $WORKSPACE_DIR/reports/opa/opa-result.txt || true
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            sh '''
                docker rm -f $APP_CONTAINER 2>/dev/null || true
                docker rm -f $MYSQL_CONTAINER 2>/dev/null || true
                docker network rm $DOCKER_NETWORK 2>/dev/null || true
            '''
        }
        success {
            echo '✅ Pipeline DevSecOps terminé avec succès'
        }
        failure {
            echo '❌ Pipeline échoué — vérifier les logs'
        }
    }
}
