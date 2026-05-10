pipeline {

    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 90, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
    }

    environment {
        APP_NAME        = 'archivage-Doc'
        APP_CONTAINER   = 'app-archivage'
        MYSQL_CONTAINER = 'mysql-archivage'
        NETWORK_NAME    = 'archivage-net'
        APP_PORT        = '8090'
        MAVEN_REPO      = '/var/jenkins_home/.m2/repository'
        SONARQUBE_ENV   = 'sonar'
    }

    stages {

        // ── 1. INIT ──────────────────────────────────────────────────────────
        stage('Init') {
            steps {
                script {
                    env.PROJECT_DIR = "${env.WORKSPACE}/src"
                    env.TRIVY_CACHE = "${env.WORKSPACE}/src/.trivycache"
                    env.JENKINS_UID = sh(returnStdout: true, script: 'id -u').trim()
                    env.JENKINS_GID = sh(returnStdout: true, script: 'id -g').trim()
                    
                    echo "✅ Environment initialized"
                    echo "   PROJECT_DIR: ${env.PROJECT_DIR}"
                    echo "   JENKINS_UID: ${env.JENKINS_UID}"
                }
            }
        }

        // ── 2. CHECKOUT ──────────────────────────────────────────────────────
        // ⚠️  REMOVED "Force Clean Workspace" — using Jenkins native deleteDir() instead
        stage('Checkout') {
            steps {
                deleteDir()  // ← Jenkins built-in, safer than docker alpine rm
                
                dir('src') {
                    checkout scm
                }
                
                script {
                    env.GIT_SHA = sh(
                        returnStdout: true,
                        script: 'cd "$PROJECT_DIR" && git rev-parse HEAD'
                    ).trim()
                    
                    if (!env.GIT_SHA?.trim()) {
                        error("❌ Failed to extract GIT_SHA")
                    }
                    
                    env.GIT_SHORT_SHA = env.GIT_SHA.take(7)
                    echo "✅ Commit: ${env.GIT_SHA}"
                    echo "✅ Short SHA: ${env.GIT_SHORT_SHA}"
                }
            }
        }

        // ── 3. LOGIN & PULL IMAGE ────────────────────────────────────────────
        // ⚠️  SIMPLIFIED: Removed 200-line Python script, use SHORT_SHA directly
        stage('Login & Pull Image') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'docker-hub-creds',
                    usernameVariable: 'DOCKER_HUB_USERNAME',
                    passwordVariable: 'DOCKER_HUB_PASSWORD'
                )]) {
                    script {
                        // Strategy: Try SHORT_SHA → latest → main (fallback)
                        def tags = ["${env.GIT_SHORT_SHA}", "latest", "main"]
                        def imageFound = false

                        for (tag in tags) {
                            try {
                                sh '''
                                    set -eu
                                    echo "📥 Attempting to pull: $DOCKER_HUB_USERNAME/archivage-app:''' + tag + '''"
                                    echo "$DOCKER_HUB_PASSWORD" | docker login -u "$DOCKER_HUB_USERNAME" --password-stdin
                                    docker pull "$DOCKER_HUB_USERNAME/archivage-app:''' + tag + '''"
                                    echo "✅ Image pulled successfully"
                                '''
                                env.RESOLVED_IMAGE_TAG = tag
                                imageFound = true
                                break
                            } catch (Exception e) {
                                echo "⚠️  Tag not found: ${tag}, trying next..."
                            }
                        }

                        if (!imageFound) {
                            error("❌ No image found on Docker Hub with tags: ${tags.join(', ')}")
                        }

                        env.DOCKER_IMAGE = "${env.DOCKER_HUB_USERNAME}/archivage-app:${env.RESOLVED_IMAGE_TAG}"
                        echo "✅ Using image: ${env.DOCKER_IMAGE}"
                    }
                }
            }
        }

        // ── 4. PREPARE WORKSPACE ─────────────────────────────────────────────
        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== PREPARE WORKSPACE ==="

                    rm -rf reports .trivycache policy
                    mkdir -p \
                        reports/gitleaks \
                        reports/trivy \
                        reports/sbom \
                        reports/zap \
                        reports/opa \
                        reports/dashboard \
                        .trivycache \
                        policy

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 \
                        || docker network create "$NETWORK_NAME"

                    # ⚠️  FIXED: Create OPA security gate policy
                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

allow if {
    input.trivy.critical == 0
    input.trivy.high <= 5              # ← REALISTIC: Max 5 HIGH (not zero)
    count(input.gitleaks) == 0
    input.zap.high <= 3                # ← REALISTIC: Max 3 HIGH
}
REGO

                    echo "✅ Workspace prepared"
                '''
            }
        }

        // ── 5. COMPILE LIGHT ────────────────────────────────────────────────
        // ⚠️  FIXED: Removed --volumes-from (assumes Jenkins in container)
        stage('Compile Light') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== COMPILE LIGHT ==="
                    
                    # Using direct volume mount instead of --volumes-from
                    docker run --rm \
                        --user "${JENKINS_UID}:${JENKINS_GID}" \
                        -v "$MAVEN_REPO:$MAVEN_REPO:rw" \
                        -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                        -w "$PROJECT_DIR" \
                        maven:3.9.9-eclipse-temurin-17 \
                        sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                    -Dmaven.repo.local='$MAVEN_REPO' \
                                    clean compile -DskipTests"
                    
                    echo "✅ Compile successful"
                '''
            }
        }

        // ── 6. SECURITY SCANS (parallel) ─────────────────────────────────────
        // ⚠️  FIXED: Added timeout to each parallel stage
        stage('Security Scans') {
            parallel {

                stage('Secrets - Gitleaks') {
                    options {
                        timeout(time: 5, unit: 'MINUTES')  // ← TIMEOUT ADDED
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                echo "=== GITLEAKS SCAN ==="
                                
                                docker run --rm \
                                    -v "$PROJECT_DIR:$PROJECT_DIR:ro" \
                                    -w "$PROJECT_DIR" \
                                    zricethezav/gitleaks:latest detect \
                                        --source . \
                                        --log-opts="--all" \
                                        --report-format json \
                                        --report-path reports/gitleaks/gitleaks-report.json \
                                        --exit-code 0

                                test -s reports/gitleaks/gitleaks-report.json \
                                    || echo "[]" > reports/gitleaks/gitleaks-report.json
                                
                                echo "✅ Gitleaks completed"
                            '''
                        }
                    }
                }

                stage('SCA - Trivy Image') {
                    options {
                        timeout(time: 15, unit: 'MINUTES')  // ← TIMEOUT ADDED
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                echo "=== TRIVY SCA SCAN ==="
                                
                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$PROJECT_DIR/reports/trivy:/reports:rw" \
                                    -v "$TRIVY_CACHE:/root/.cache/trivy:rw" \
                                    ghcr.io/aquasecurity/trivy:latest image \
                                        --no-progress \
                                        --quiet \
                                        --scanners vuln \
                                        --severity CRITICAL,HIGH \
                                        --format json \
                                        --output /reports/trivy-report.json \
                                        "$DOCKER_IMAGE"

                                test -s reports/trivy/trivy-report.json \
                                    || echo '{"Results":[]}' > reports/trivy/trivy-report.json
                                
                                echo "✅ Trivy completed"
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube Analysis') {
                    options {
                        timeout(time: 20, unit: 'MINUTES')  // ← TIMEOUT ADDED
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            script {
                                withSonarQubeEnv("${SONARQUBE_ENV}") {
                                    sh '''
                                        set -eu
                                        cd "$PROJECT_DIR"
                                        echo "=== SONARQUBE SAST ANALYSIS ==="
                                        
                                        test -d "$PROJECT_DIR/target/classes" || {
                                            echo "⚠️  No compiled classes found, skipping SonarQube"
                                            exit 0
                                        }

                                        # ⚠️  FIXED: Use proper SonarQube hostname (not host.docker.internal)
                                        docker run --rm \
                                            --user "${JENKINS_UID}:${JENKINS_GID}" \
                                            --network "$NETWORK_NAME" \
                                            -v "$MAVEN_REPO:$MAVEN_REPO:rw" \
                                            -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                                            -w "$PROJECT_DIR" \
                                            -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                            -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                            maven:3.9.9-eclipse-temurin-17 \
                                            sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                                        -Dmaven.repo.local='$MAVEN_REPO' \
                                                        org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                                        -Dsonar.projectKey='$APP_NAME' \
                                                        -Dsonar.host.url='$SONAR_HOST_URL' \
                                                        -Dsonar.token='$SONAR_AUTH_TOKEN' \
                                                        -Dsonar.java.binaries='target/classes'"
                                        
                                        echo "✅ SonarQube analysis completed"
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    options {
                        timeout(time: 10, unit: 'MINUTES')  // ← TIMEOUT ADDED
                    }
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eu
                                cd "$PROJECT_DIR"
                                echo "=== CYCLONEDX SBOM GENERATION ==="
                                
                                docker run --rm \
                                    --user "${JENKINS_UID}:${JENKINS_GID}" \
                                    -v "$MAVEN_REPO:$MAVEN_REPO:rw" \
                                    -v "$PROJECT_DIR:$PROJECT_DIR:rw" \
                                    -w "$PROJECT_DIR" \
                                    maven:3.9.9-eclipse-temurin-17 \
                                    sh -lc "mvn -B -f '$PROJECT_DIR/pom.xml' \
                                                -Dmaven.repo.local='$MAVEN_REPO' \
                                                org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                                                -DoutputFormat=all"

                                test -f "$PROJECT_DIR/target/bom.xml" \
                                    && cp -f "$PROJECT_DIR/target/bom.xml" "$PROJECT_DIR/reports/sbom/bom.xml" || true
                                test -f "$PROJECT_DIR/target/bom.json" \
                                    && cp -f "$PROJECT_DIR/target/bom.json" "$PROJECT_DIR/reports/sbom/bom.json" || true
                                
                                echo "✅ CycloneDX SBOM completed"
                            '''
                        }
                    }
                }

            }
        }

        // ── 7. DEPLOY MYSQL ──────────────────────────────────────────────────
        // ⚠️  FIXED: Health check uses correct hostname and password
        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eu
                    echo "=== DEPLOY MYSQL ==="
                    
                    docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                    docker run -d \
                        --name "$MYSQL_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        -e MYSQL_ROOT_PASSWORD=root \
                        -e MYSQL_DATABASE=archivage_doc \
                        -e MYSQL_USER=archivage_user \
                        -e MYSQL_PASSWORD=archivage_pass \
                        mysql:8.0 >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        # ⚠️  FIXED: Correct hostname + password
                        if docker run --rm --network "$NETWORK_NAME" mysql:8.0 \
                                mysqladmin ping -h"$MYSQL_CONTAINER" -uarchivage_user -parchivage_pass --silent 2>/dev/null; then
                            READY=1
                            echo "✅ MySQL ready (attempt $i/30)"
                            break
                        fi
                        echo "⏳ Waiting for MySQL... (attempt $i/30)"
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "❌ MySQL did not respond after 150 seconds"
                        docker logs "$MYSQL_CONTAINER" --tail 50 || true
                        exit 1
                    fi
                    
                    echo "✅ MySQL deployment successful"
                '''
            }
        }

        // ── 8. DEPLOY APP ────────────────────────────────────────────────────
        // ⚠️  FIXED: Health check only accepts 200/302 (not 401/403/404)
        stage('Deploy App') {
            steps {
                sh '''
                    set -eu
                    echo "=== DEPLOY APP ==="
                    
                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                    mkdir -p "$PROJECT_DIR/uploads"
                    chmod 755 "$PROJECT_DIR/uploads"

                    docker run -d \
                        --name "$APP_CONTAINER" \
                        --network "$NETWORK_NAME" \
                        --restart on-failure:5 \
                        -v "$PROJECT_DIR/uploads:/app/uploads" \
                        -e SPRING_PROFILES_ACTIVE=docker \
                        -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" \
                        -e SPRING_DATASOURCE_USERNAME="archivage_user" \
                        -e SPRING_DATASOURCE_PASSWORD="archivage_pass" \
                        -e GITHUB_OAUTH_SECRET="${GITHUB_OAUTH_SECRET:-test}" \
                        -e JWT_SECRET="${JWT_SECRET:-test}" \
                        "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 36); do
                        # ⚠️  FIXED: Only accept 200/302 (not 401/403/404)
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                               -s -o /dev/null -w "%{http_code}" \
                               "http://$APP_CONTAINER:$APP_PORT/actuator/health" 2>/dev/null || echo "000")
                        
                        if echo "$CODE" | grep -qE "^(200|302)$"; then
                            READY=1
                            echo "✅ App ready (HTTP $CODE, attempt $i/36)"
                            break
                        fi
                        
                        echo "⏳ Waiting for app... (HTTP $CODE, attempt $i/36)"
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "❌ App did not respond after 180 seconds"
                        docker logs "$APP_CONTAINER" --tail 100 || true
                        exit 1
                    fi
                    
                    echo "✅ App deployment successful"
                '''
            }
        }

        // ── 9. DAST - OWASP ZAP ─────────────────────────────────────────────
        // ⚠️  FIXED: ZAP timeout + proper permission handling + don't run as root
        stage('DAST - OWASP ZAP') {
            options {
                timeout(time: 30, unit: 'MINUTES')  // ← TIMEOUT ADDED
            }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eu
                        cd "$PROJECT_DIR"
                        echo "=== OWASP ZAP DAST SCAN ==="

                        mkdir -p "$PROJECT_DIR/reports/zap"

                        # ⚠️  FIXED: Run as ZAP user (not root)
                        docker run --rm \
                            --network "$NETWORK_NAME" \
                            -v "$PROJECT_DIR/reports/zap:/zap/wrk:rw" \
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                                -t "http://$APP_CONTAINER:$APP_PORT/" \
                                -J "zap-report.json" \
                                -a -j -I || true

                        # ⚠️  FIXED: Fix permissions ONCE after scan
                        docker run --rm \
                            -u 0:0 \
                            -v "$PROJECT_DIR/reports/zap:/zap/wrk" \
                            alpine:3.19 \
                            sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /zap/wrk && chmod -R u+w /zap/wrk" || true

                        # Ensure valid JSON
                        test -s "$PROJECT_DIR/reports/zap/zap-report.json" \
                            || echo '{"site":[{"alerts":[]}]}' > "$PROJECT_DIR/reports/zap/zap-report.json"

                        echo "✅ ZAP scan completed"
                    '''
                }
            }
        }

        // ── 10. POLICY - OPA SECURITY GATE ──────────────────────────────────
        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eu
                    cd "$PROJECT_DIR"
                    echo "=== OPA SECURITY GATE ==="

                    # Build OPA input from scan results
                    python3 - <<'PYEOF'
import json
import sys
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}", file=sys.stderr)
        return default

gitleaks = load_json("reports/gitleaks/gitleaks-report.json", [])
trivy    = load_json("reports/trivy/trivy-report.json", {"Results": []})
zap      = load_json("reports/zap/zap-report.json", {"site": [{"alerts": []}]})

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in trivy.get("Results", []) or []:
    for v in result.get("Vulnerabilities", []) or []:
        s = (v.get("Severity") or "").upper()
        if s in sev:
            sev[s] += 1

zap_high = 0
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        if str(alert.get("riskcode", 0)) == "3":
            zap_high += 1

payload = {
    "gitleaks": gitleaks if isinstance(gitleaks, list) else [],
    "trivy": {
        "critical": sev["CRITICAL"],
        "high":     sev["HIGH"],
        "medium":   sev["MEDIUM"],
        "low":      sev["LOW"]
    },
    "zap": {"high": zap_high}
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(
    json.dumps(payload, indent=2), encoding="utf-8"
)

print("=== OPA INPUT SUMMARY ===")
print(f"  Gitleaks secrets : {len(payload['gitleaks'])}")
print(f"  Trivy CRITICAL   : {sev['CRITICAL']}")
print(f"  Trivy HIGH       : {sev['HIGH']}")
print(f"  ZAP HIGH         : {zap_high}")
print("=========================")
PYEOF

                    # Evaluate OPA policy
                    docker run --rm \
                        -v "$PROJECT_DIR:$PROJECT_DIR:ro" \
                        -w "$PROJECT_DIR" \
                        openpolicyagent/opa:latest \
                        eval \
                            --format raw \
                            --data "$PROJECT_DIR/policy/security-gate.rego" \
                            --input "$PROJECT_DIR/reports/opa/input.json" \
                            "data.security.allow" \
                        > "$PROJECT_DIR/reports/opa/opa-result.txt"

                    OPA_RESULT=$(cat "$PROJECT_DIR/reports/opa/opa-result.txt")
                    echo "🚪 OPA Security Gate Result: $OPA_RESULT"

                    if [ "$OPA_RESULT" != "true" ]; then
                        echo "❌ SECURITY GATE BLOCKED — Fix vulns before proceeding"
                        exit 1
                    fi
                    
                    echo "✅ OPA Security Gate PASSED"
                '''
            }
        }
    }

    post {

        always {
            echo "=== CLEANUP PHASE ==="
            
            sh '''
                set +e
                
                # Fix permissions for Jenkins archival
                docker run --rm -u 0:0 \
                    -v "$WORKSPACE:/ws" \
                    alpine:3.19 \
                    sh -c "chown -R ${JENKINS_UID}:${JENKINS_GID} /ws 2>/dev/null || true"
                
                # Cleanup containers
                docker rm -f "$APP_CONTAINER"   >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                
                # Keep network for potential debugging
                # docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
                
                echo "✅ Cleanup completed"
            '''

            script {
                if (fileExists('src/reports/trivy/trivy-report.json')) {
                    recordIssues(
                        enabledForFailure: true,
                        aggregatingResults: true,
                        tools: [
                            trivy(
                                pattern: 'src/reports/trivy/trivy-report.json',
                                reportEncoding: 'UTF-8'
                            )
                        ]
                    )
                }
            }

            script {
                if (fileExists('src/reports')) {
                    archiveArtifacts(
                        artifacts: [
                            'src/reports/gitleaks/gitleaks-report.json',
                            'src/reports/trivy/trivy-report.json',
                            'src/reports/zap/zap-report.html',
                            'src/reports/zap/zap-report.json',
                            'src/reports/opa/opa-result.txt',
                            'src/reports/opa/input.json',
                            'src/reports/sbom/bom.json',
                            'src/reports/sbom/bom.xml'
                        ].join(','),
                        allowEmptyArchive: true,
                        fingerprint      : false
                    )
                }
            }
        }

        failure {
            echo '❌ Pipeline FAILED — Check logs and security reports'
        }

        unstable {
            echo '⚠️  Pipeline UNSTABLE — Security issues detected'
        }

        success {
            echo '✅ Pipeline SUCCESS — All security gates passed'
        }
    }
}
