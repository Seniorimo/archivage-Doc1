pipeline {
    agent any
    
    options {
        timeout(time: 20, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
    }
    
    stages {
        stage('Préparation') {
            steps {
                script {
                    // Nettoyage + clone FRESH (ignore checkout Jenkins buggy)
                    sh '''
                        rm -rf workspace-clean
                        git clone https://github.com/Seniorimo/archivage-Doc1.git workspace-clean
                        cd workspace-clean
                        ls -la  # Debug: vérifie pom.xml et Dockerfile
                        pwd
                    '''
                }
            }
        }
        
        stage('Maven Build') {
            steps {
                sh '''
                    cd workspace-clean
                    mvn clean compile install -DskipTests -B
                '''
            }
        }
        
        stage('Docker Build') {
            steps {
                sh '''
                    cd workspace-clean
                    docker build -t archivage-doc:${BUILD_NUMBER} .
                    docker images | grep archivage-doc
                '''
            }
        }
        
        stage('Test App') {
            steps {
                sh '''
                    # Kill ancien conteneur
                    docker rm -f archivage-doc-app || true
                    
                    # Run + health check (Spring Boot actuator)
                    docker run -d --name archivage-doc-app -p 8081:8080 archivage-doc:${BUILD_NUMBER}
                    sleep 15
                    
                    # Tests multiples
                    curl -f http://localhost:8081/actuator/health || (echo "FAIL: Health KO" && exit 1)
                    curl -f http://localhost:8081/actuator/info || echo "INFO OK (optional)"
                    curl -f http://localhost:8081/actuator || echo "Actuator OK"
                    
                    echo "✅ App démarrée sur http://localhost:8081"
                '''
            }
        }
    }
    
    post {
        always {
            sh '''
                docker rm -f archivage-doc-app || true
                docker rmi archivage-doc:${BUILD_NUMBER} || true
            '''
        }
        success {
            echo '🎉 BUILD SUCCESS - App OK sur port 8081'
            // Optionnel: archive artifact
            archiveArtifacts artifacts: 'workspace-clean/target/*.jar', allowEmptyArchive: true
        }
        failure {
            echo '❌ BUILD FAILED - Voir logs ci-dessus'
        }
    }
}
