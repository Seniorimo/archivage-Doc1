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
                        mkdir -p "$WORKSPACE/reports/gitleaks"

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE" \
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
                        -f "$WORKSPACE/pom.xml" \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        clean package -DskipTests
                '''
            }
        }

        stage('Trivy SCA Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p "$WORKSPACE/reports/trivy"

                        docker run --rm \
                          --volumes-from jenkins \
                          -v "$WORKSPACE/reports/trivy:/report" \
                          ghcr.io/aquasecurity/trivy:latest fs \
                          --scanners vuln \
                          --severity MEDIUM,HIGH,CRITICAL \
                          --format json \
                          --output /report/trivy-report.json \
                          "$WORKSPACE" || true

                        docker run --rm \
                          --volumes-from jenkins \
                          -v "$WORKSPACE/reports/trivy:/report" \
                          ghcr.io/aquasecurity/trivy:latest fs \
                          --scanners vuln \
                          --severity MEDIUM,HIGH,CRITICAL \
                          --format template \
                          --template "@contrib/html.tpl" \
                          --output /report/trivy-report.html \
                          "$WORKSPACE" || true
                    '''
                }
            }
        }

        stage('CycloneDX SBOM') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p "$WORKSPACE/reports/sbom"

                        docker run --rm \
                          --volumes-from jenkins \
                          maven:3.9.9-eclipse-temurin-17 \
                          sh -lc "
                            mvn -B \
                              -f '$WORKSPACE/pom.xml' \
                              -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                              org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                              -DoutputFormat=all &&
                            cp -f '$WORKSPACE/target/bom.xml'  '$WORKSPACE/reports/sbom/bom.xml' &&
                            cp -f '$WORKSPACE/target/bom.json' '$WORKSPACE/reports/sbom/bom.json'
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
                              -f '$WORKSPACE/pom.xml' \
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
                    docker rm -f "$MYSQL_CONTAINER" 2>/dev/null || true
                    docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK"

                    docker run -d \
                      --name "$MYSQL_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASS" \
                      -e MYSQL_DATABASE="$MYSQL_DATABASE" \
                      -e MYSQL_USER="$MYSQL_USER" \
                      -e MYSQL_PASSWORD="$MYSQL_PASS" \
                      mysql:8.0

                    echo "Waiting for MySQL..."
                    sleep 25
                    docker logs "$MYSQL_CONTAINER" --tail 20 || true
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    docker rm -f "$APP_CONTAINER" 2>/dev/null || true

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$DOCKER_NETWORK" \
                      --volumes-from jenkins \
                      --add-host=host.docker.internal:host-gateway \
                      -p "$APP_PORT:$APP_PORT" \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B \
                        -f '$WORKSPACE/pom.xml' \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        spring-boot:run \
                        -Dspring-boot.run.arguments='--server.port=$APP_PORT --spring.datasource.url=jdbc:mysql://$MYSQL_CONTAINER:3306/$MYSQL_DATABASE --spring.datasource.username=$MYSQL_USER --spring.datasource.password=$MYSQL_PASS'"

                    echo "Waiting for Spring Boot..."
                    sleep 10

                    READY=0
                    for i in $(seq 1 12); do
                      STATUS=$(docker run --rm \
                        --network "$DOCKER_NETWORK" \
                        curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" \
                        "http://$APP_CONTAINER:$APP_PORT/" || true)

                      echo "Attempt $i/12 -> HTTP status: $STATUS"

                      if echo "$STATUS" | grep -qE "200|302"; then
                        READY=1
                        break
                      fi

                      sleep 10
                    done

                    if [ "$READY" -ne 1 ]; then
                      echo "Application did not become ready. Container logs:"
                      docker logs "$APP_CONTAINER" --tail 200 || true
                      exit 1
                    fi
                '''
            }
        }

        stage('ZAP DAST Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p "$WORKSPACE/reports/zap"

                        docker run --rm \
                          --user root \
                          --add-host=host.docker.internal:host-gateway \
                          --volumes-from jenkins \
                          -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                          ghcr.io/zaproxy/zaproxy:stable \
                          zap-baseline.py \
                          -t "http://host.docker.internal:$APP_PORT" \
                          -r zap-report.html \
                          -J zap-report.json \
                          -I || true
                    '''
                }
            }
        }

        stage('Security Dashboard') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p "$WORKSPACE/reports/dashboard"

                        TRIVY_HIGH=0
                        TRIVY_MEDIUM=0
                        ZAP_HIGH=0
                        ZAP_MEDIUM=0

                        if [ -f "$WORKSPACE/reports/trivy/trivy-report.json" ]; then
                          TRIVY_HIGH=$(grep -o '"Severity":"HIGH"' "$WORKSPACE/reports/trivy/trivy-report.json" | wc -l | tr -d ' ' || true)
                          TRIVY_MEDIUM=$(grep -o '"Severity":"MEDIUM"' "$WORKSPACE/reports/trivy/trivy-report.json" | wc -l | tr -d ' ' || true)
                        fi

                        if [ -f "$WORKSPACE/reports/zap/zap-report.json" ]; then
                          ZAP_HIGH=$(grep -o '"riskcode":"3"' "$WORKSPACE/reports/zap/zap-report.json" | wc -l | tr -d ' ' || true)
                          ZAP_MEDIUM=$(grep -o '"riskcode":"2"' "$WORKSPACE/reports/zap/zap-report.json" | wc -l | tr -d ' ' || true)
                        fi

                        cat > "$WORKSPACE/reports/dashboard/index.html" <<EOF
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Security Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 30px; background: #f7f9fc; color: #222; }
    h1 { margin-bottom: 10px; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
    .card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,.08); text-align: center; }
    .num { font-size: 30px; font-weight: bold; margin-top: 8px; }
    .high { border-top: 5px solid #d32f2f; }
    .medium { border-top: 5px solid #f9a825; }
    table { width: 100%; border-collapse: collapse; background: white; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: center; }
    th { background: #263238; color: white; }
    .note { margin-top: 20px; color: #555; }
  </style>
</head>
<body>
  <h1>Security Dashboard</h1>
  <p>Vue synthese des vulnerabilites Medium et High publiees par Jenkins.</p>

  <div class="grid">
    <div class="card high">
      <div>Trivy High</div>
      <div class="num">${TRIVY_HIGH}</div>
    </div>
    <div class="card medium">
      <div>Trivy Medium</div>
      <div class="num">${TRIVY_MEDIUM}</div>
    </div>
    <div class="card high">
      <div>ZAP High</div>
      <div class="num">${ZAP_HIGH}</div>
    </div>
    <div class="card medium">
      <div>ZAP Medium</div>
      <div class="num">${ZAP_MEDIUM}</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Scanner</th>
        <th>High</th>
        <th>Medium</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Trivy</td>
        <td>${TRIVY_HIGH}</td>
        <td>${TRIVY_MEDIUM}</td>
      </tr>
      <tr>
        <td>OWASP ZAP</td>
        <td>${ZAP_HIGH}</td>
        <td>${ZAP_MEDIUM}</td>
      </tr>
    </tbody>
  </table>

  <p class="note">Consultez aussi les rapports publies dans Jenkins : "Trivy Report" et "ZAP Report".</p>
</body>
</html>
EOF
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true

            publishHTML(target: [
                reportName: 'Security Dashboard',
                reportDir: 'reports/dashboard',
                reportFiles: 'index.html',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            publishHTML(target: [
                reportName: 'Trivy Report',
                reportDir: 'reports/trivy',
                reportFiles: 'trivy-report.html',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            publishHTML(target: [
                reportName: 'ZAP Report',
                reportDir: 'reports/zap',
                reportFiles: 'zap-report.html',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            sh '''
                docker rm -f "$APP_CONTAINER" 2>/dev/null || true
                docker rm -f "$MYSQL_CONTAINER" 2>/dev/null || true
                docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
            '''
        }

        success {
            echo '✅ Pipeline DevSecOps termine avec succes'
        }

        unstable {
            echo '⚠️ Pipeline termine, mais certains scans securite ont remonte des alertes ou des erreurs non bloquantes'
        }

        failure {
            echo '❌ Pipeline echoue — verifier les logs'
        }
    }
}
