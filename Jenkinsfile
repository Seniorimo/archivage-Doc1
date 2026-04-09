pipeline {
    agent any

    environment {
        SONAR_TOKEN        = credentials('sonar-token')
        APP_PORT           = '8081'
        MYSQL_ROOT_PASS    = 'root'
        MYSQL_DATABASE     = 'archivage_db'
        MYSQL_USER         = 'archivage_user'
        MYSQL_PASS         = 'archivage_pass'
        DOCKER_NETWORK     = 'archivage-net'
        MYSQL_CONTAINER    = 'mysql-archivage'
        APP_CONTAINER      = 'app-archivage'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build & Test') {
            steps {
                sh '''
                    docker run --rm \
                      --volumes-from jenkins \
                      -w /var/jenkins_home/workspace/DevSecOps-PFE-Test \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B \
                        -f /var/jenkins_home/workspace/DevSecOps-PFE-Test/pom.xml \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        clean package -DskipTests
                '''
            }
        }

        stage('SonarQube Analysis') {
            steps {
                sh '''
                    docker run --rm \
                      --volumes-from jenkins \
                      --add-host=host.docker.internal:host-gateway \
                      -w /var/jenkins_home/workspace/DevSecOps-PFE-Test \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B \
                        -f /var/jenkins_home/workspace/DevSecOps-PFE-Test/pom.xml \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                        -Dsonar.projectKey=archivage-doc \
                        -Dsonar.host.url=http://host.docker.internal:9000 \
                        -Dsonar.login=${SONAR_TOKEN} \
                        -Dsonar.java.binaries=target/classes
                '''
            }
        }

        stage('Deploy App for DAST') {
            steps {
                sh '''
                    # Créer le réseau s'il n'existe pas
                    docker network inspect ${DOCKER_NETWORK} >/dev/null 2>&1 \
                      || docker network create ${DOCKER_NETWORK}

                    # Lancer MySQL
                    docker run -d \
                      --name ${MYSQL_CONTAINER} \
                      --network ${DOCKER_NETWORK} \
                      -e MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASS} \
                      -e MYSQL_DATABASE=${MYSQL_DATABASE} \
                      -e MYSQL_USER=${MYSQL_USER} \
                      -e MYSQL_PASSWORD=${MYSQL_PASS} \
                      mysql:8.0

                    # Attendre que MySQL soit prêt
                    echo "Waiting for MySQL..."
                    sleep 20

                    # Lancer l'application Spring Boot
                    docker run -d \
                      --name ${APP_CONTAINER} \
                      --network ${DOCKER_NETWORK} \
                      --volumes-from jenkins \
                      --add-host=host.docker.internal:host-gateway \
                      -p ${APP_PORT}:${APP_PORT} \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B \
                        -f /var/jenkins_home/workspace/DevSecOps-PFE-Test/pom.xml \
                        -Dmaven.repo.local=/var/jenkins_home/.m2/repository \
                        spring-boot:run \
                        -Dspring-boot.run.arguments='\
                          --server.port=${APP_PORT} \
                          --spring.datasource.url=jdbc:mysql://${MYSQL_CONTAINER}:3306/${MYSQL_DATABASE} \
                          --spring.datasource.username=${MYSQL_USER} \
                          --spring.datasource.password=${MYSQL_PASS}'"

                    # Attendre que l'app soit prête
                    echo "Waiting for Spring Boot..."
                    sleep 30

                    # Vérifier que l'app répond
                    curl -s -o /dev/null -w "%{http_code}" http://localhost:${APP_PORT}/ | grep -E "200|302"
                '''
            }
        }

        stage('ZAP DAST Scan') {
            steps {
                sh '''
                    mkdir -p /var/jenkins_home/workspace/DevSecOps-PFE-Test/reports/zap

                    docker run --rm \
                      --user root \
                      --add-host=host.docker.internal:host-gateway \
                      --volumes-from jenkins \
                      -v /var/jenkins_home/workspace/DevSecOps-PFE-Test/reports/zap:/zap/wrk:rw \
                      ghcr.io/zaproxy/zaproxy:stable \
                      zap-baseline.py \
                      -t http://host.docker.internal:${APP_PORT} \
                      -r zap-report.html \
                      -J zap-report.json \
                      -I
                '''
            }
        }
    }

    post {
        always {
            // Archiver les rapports
            archiveArtifacts artifacts: 'reports/zap/zap-report.html, reports/zap/zap-report.json',
                             allowEmptyArchive: true

            // Nettoyer les conteneurs
            sh '''
                docker rm -f ${APP_CONTAINER}  || true
                docker rm -f ${MYSQL_CONTAINER} || true
                docker network rm ${DOCKER_NETWORK} || true
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
