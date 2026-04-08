pipeline {
  agent any

  tools {
    // Assurez-vous que ces outils existent dans Jenkins (Global Tool Configuration)
    jdk 'JDK17'
    maven 'Maven3'
  }

  options {
    timestamps()
    ansiColor('xterm')
  }

  environment {
    // Identifiant du serveur SonarQube configuré dans Jenkins (Manage Jenkins > System)
    SONARQUBE_SERVER = 'SonarQubeServer'
    // Nom de l'artefact final archivé (adapter selon votre packaging)
    ARTIFACT_PATTERN = 'target/*.jar, target/*.war'
  }

  stages {
    // ------------------------------------------------------------------------------------
    // Stage 1 - Checkout
    // Récupère le code source depuis le dépôt Git configuré au niveau du job Jenkins.
    // Avec "checkout scm", Jenkins utilise automatiquement la configuration SCM du job.
    // ------------------------------------------------------------------------------------
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    // ------------------------------------------------------------------------------------
    // Stage 2 - Build
    // Compile et package l'application Java avec Maven.
    // Les tests sont explicitement ignorés ici pour respecter votre exigence:
    // "mvn clean install -DskipTests".
    // ------------------------------------------------------------------------------------
    stage('Build') {
      steps {
        sh 'mvn -B clean install -DskipTests'
      }
    }

    // ------------------------------------------------------------------------------------
    // Stage 3 - SCA (OWASP Dependency-Check)
    // Lance l'analyse des dépendances pour identifier les composants vulnérables.
    // Le build échoue automatiquement si des vulnérabilités critiques sont détectées
    // via le seuil CVSS défini (failBuildOnCVSS=9).
    //
    // Pré-requis:
    // - Le plugin Maven OWASP Dependency-Check doit être disponible
    //   (idéalement déclaré dans le pom.xml, sinon invoqué ici par son groupId/artifactId).
    // ------------------------------------------------------------------------------------
    stage('SCA - Dependency Check') {
      steps {
        sh '''
          mvn -B org.owasp:dependency-check-maven:check \
            -Dformat=HTML \
            -DoutputDirectory=target/dependency-check-report \
            -DfailBuildOnCVSS=9
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'target/dependency-check-report/**', allowEmptyArchive: true
        }
      }
    }

    // ------------------------------------------------------------------------------------
    // Stage 4 - SAST (SonarQube)
    // Exécute l'analyse statique du code avec SonarQube (bugs, code smells, vulnérabilités).
    // L'étape est encapsulée dans "withSonarQubeEnv" pour injecter automatiquement
    // les variables/URL/token configurés dans Jenkins.
    //
    // Pré-requis:
    // - Plugin Jenkins "SonarQube Scanner" installé.
    // - Serveur SonarQube enregistré dans Jenkins avec le nom SONARQUBE_SERVER.
    // ------------------------------------------------------------------------------------
    stage('SAST - SonarQube') {
      steps {
        withSonarQubeEnv("${SONARQUBE_SERVER}") {
          sh 'mvn -B sonar:sonar'
        }
      }
    }

    // ------------------------------------------------------------------------------------
    // Stage 5 - Archive / Deploy (optionnel pour l'instant)
    // Archive les artefacts produits (.jar/.war) afin de les conserver dans Jenkins.
    // Cela prépare également le terrain pour un futur stage de déploiement.
    // ------------------------------------------------------------------------------------
    stage('Archive') {
      steps {
        archiveArtifacts artifacts: "${ARTIFACT_PATTERN}", fingerprint: true
      }
    }
  }

  post {
    // Notification simple en cas de succès global de la pipeline
    success {
      echo 'SUCCESS: la pipeline CI/CD s’est terminée correctement (Build + SCA + SAST + Archive).'
    }

    // Notification simple en cas d’échec de la pipeline
    failure {
      echo 'FAILURE: la pipeline CI/CD a échoué. Vérifiez les logs des stages pour identifier la cause.'
    }

    // Message final toujours affiché (audit trail minimal)
    always {
      echo "Pipeline terminée - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
    }
  }
}
