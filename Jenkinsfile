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
                    sleep 35

                    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$APP_PORT/ || true)
                    echo "HTTP status: $STATUS"
                    echo "$STATUS" | grep -qE "200|302"
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
    }

    post {
        always {
            node {
                archiveArtifacts artifacts: 'reports/zap/**', allowEmptyArchive: true
                sh '''
                    docker rm -f $APP_CONTAINER 2>/dev/null || true
                    docker rm -f $MYSQL_CONTAINER 2>/dev/null || true
                    docker network rm $DOCKER_NETWORK 2>/dev/null || true
                '''
            }
        }
        success {
            echo '✅ Pipeline DevSecOps terminé avec succès'
        }
        failure {
            echo '❌ Pipeline échoué — vérifier les logs'
        }
    }
}
