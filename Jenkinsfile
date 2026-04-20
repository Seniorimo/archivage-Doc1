pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        APP_NAME        = 'archivage-Doc'
        APP_CONTAINER   = 'app-archivage'
        MYSQL_CONTAINER = 'mysql-archivage'
        NETWORK_NAME    = 'archivage-net'
        APP_PORT        = '8090'
        DOCKER_IMAGE    = "archivage-app:${env.BUILD_NUMBER}"
        MAVEN_REPO      = '/var/jenkins_home/.m2/repository'
        TRIVY_CACHE     = "${WORKSPACE}/.trivycache"
        SONARQUBE_ENV   = 'sonar'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eux
                    rm -rf reports .trivycache policy .jarpath
                    mkdir -p reports/gitleaks reports/trivy reports/sbom reports/zap reports/opa .trivycache policy

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"

                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

allow if {
    input.trivy.critical == 0
    count(input.gitleaks) == 0
    input.zap.high == 0
}
REGO

                    cat > reports/opa/build_input.py <<'PYEOF'
import json
import sys
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

gitleaks = load_json("reports/gitleaks/gitleaks-report.json", [])
trivy    = load_json("reports/trivy/trivy-report.json", {"Results": []})
zap      = load_json("reports/zap/zap-report.json", {"site": [{"alerts": []}]})

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in trivy.get("Results", []):
    for v in result.get("Vulnerabilities", []) or []:
        s = (v.get("Severity") or "").upper()
        if s in sev:
            sev[s] += 1

zap_high = 0
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        if str(alert.get("riskcode", "")).strip() == "3":
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
Path("reports/opa/input.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

print("=== OPA INPUT SUMMARY ===")
print("  Gitleaks secrets : " + str(len(payload["gitleaks"])))
print("  Trivy CRITICAL   : " + str(sev["CRITICAL"]))
print("  Trivy HIGH       : " + str(sev["HIGH"]))
print("  ZAP HIGH         : " + str(zap_high))
print("=========================")

if sev["CRITICAL"] > 0:
    print("[DETAIL] CVE CRITICAL detectees :")
    for result in trivy.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            if (v.get("Severity") or "").upper() == "CRITICAL":
                print("  " + v.get("VulnerabilityID", "?")
                      + "  " + v.get("PkgName", "?")
                      + "  " + v.get("InstalledVersion", "?")
                      + " -> fix: " + v.get("FixedVersion", "N/A"))

if len(payload["gitleaks"]) > 0:
    print("[DETAIL] Secrets Gitleaks :")
    for leak in payload["gitleaks"][:10]:
        print("  Rule: " + str(leak.get("RuleID", "?"))
              + "  File: " + str(leak.get("File", "?"))
              + "  Commit: " + str(leak.get("Commit", "?"))[:8])

sys.exit(0)
PYEOF

                    cat > reports/zap/zap_to_html.py <<'ZAPEOF'
import json
from pathlib import Path

src = Path("zap-report.json")
out = Path("zap-report.html")

try:
    data = json.loads(src.read_text(encoding="utf-8"))
except Exception:
    data = {"site": [{"alerts": []}]}

RISK_LABEL = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
RISK_COLOR = {"3": "#c0392b", "2": "#e67e22", "1": "#f1c40f", "0": "#2980b9"}

all_alerts = []
target = ""
for site in data.get("site", []) or []:
    if not target:
        target = site.get("@name", site.get("name", "N/A"))
    for alert in site.get("alerts", []) or []:
        all_alerts.append(alert)

all_alerts.sort(key=lambda a: -int(str(a.get("riskcode", "0"))))

rows = ""
for a in all_alerts:
    rc   = str(a.get("riskcode", "0"))
    name = a.get("alert", a.get("name", "?"))
    desc = a.get("desc", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    sol  = a.get("solution", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
    url  = ""
    for inst in a.get("instances", [])[:1]:
        url = inst.get("uri", "")
    color = RISK_COLOR.get(rc, "#999")
    label = RISK_LABEL.get(rc, rc)
    rows += f"""<tr>
      <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{label}</span></td>
      <td><strong>{name}</strong><br><small style="color:#555">{url}</small></td>
      <td style="font-size:12px">{desc}</td>
      <td style="font-size:12px">{sol}</td>
    </tr>"""

counts = {"3": 0, "2": 0, "1": 0, "0": 0}
for a in all_alerts:
    rc = str(a.get("riskcode", "0"))
    if rc in counts:
        counts[rc] += 1

html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>ZAP Security Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
  h1 {{ color: #2c3e50; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
  .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
  .badge {{ padding: 15px 25px; border-radius: 8px; color: #fff; text-align: center; min-width: 100px; }}
  .badge .num {{ font-size: 2em; font-weight: bold; }}
  .badge .lbl {{ font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
  th {{ background: #2c3e50; color: #fff; padding: 10px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover {{ background: #fafafa; }}
  .meta {{ background: #fff; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
</style>
</head>
<body>
<h1>ZAP Baseline Scan — Security Report</h1>
<div class="meta">
  <strong>Cible :</strong> {target}<br>
  <strong>Total alertes :</strong> {len(all_alerts)}
</div>
<div class="summary">
  <div class="badge" style="background:#c0392b"><div class="num">{counts["3"]}</div><div class="lbl">HIGH</div></div>
  <div class="badge" style="background:#e67e22"><div class="num">{counts["2"]}</div><div class="lbl">MEDIUM</div></div>
  <div class="badge" style="background:#c8a200"><div class="num">{counts["1"]}</div><div class="lbl">LOW</div></div>
  <div class="badge" style="background:#2980b9"><div class="num">{counts["0"]}</div><div class="lbl">INFO</div></div>
</div>
<table>
  <thead><tr><th>Risque</th><th>Alerte</th><th>Description</th><th>Solution</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="4" style="text-align:center;padding:30px;color:#27ae60"><strong>Aucune alerte detectee</strong></td></tr>'}</tbody>
</table>
</body>
</html>"""

out.write_text(html, encoding="utf-8")
print("Rapport HTML ZAP genere : " + str(out))
ZAPEOF
                '''
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    set -eux
                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      maven:3.9.9-eclipse-temurin-17 \
                      sh -lc "mvn -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' clean package -DskipTests"

                    JARPATH=$(find "$WORKSPACE/target" -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)
                    test -n "$JARPATH"
                    test -f "$JARPATH"
                    echo "$JARPATH" > "$WORKSPACE/.jarpath"

                    docker build -t "$DOCKER_IMAGE" "$WORKSPACE"
                    echo "Image Docker construite : $DOCKER_IMAGE"
                '''
            }
        }

        stage('Security Scans') {
            parallel {
                stage('Secrets - Gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eux
                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$WORKSPACE" \
                                  zricethezav/gitleaks:latest detect \
                                  --source . \
                                  --log-opts="--all" \
                                  --report-format json \
                                  --report-path reports/gitleaks/gitleaks-report.json \
                                  --exit-code 0

                                test -s reports/gitleaks/gitleaks-report.json || echo "[]" > reports/gitleaks/gitleaks-report.json
                            '''
                        }
                    }
                }

                stage('Trivy FS Scan') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eux
                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$WORKSPACE" \
                                  -v "$TRIVY_CACHE:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs \
                                  --no-progress --quiet \
                                  --scanners vuln \
                                  --severity CRITICAL,HIGH \
                                  --format json \
                                  --output reports/trivy/trivy-report.json .

                                echo "--- RAPPORT DE SECURITE TRIVY (VUE TABLEAU) ---"
                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$WORKSPACE" \
                                  -v "$TRIVY_CACHE:/root/.cache/trivy" \
                                  ghcr.io/aquasecurity/trivy:latest fs \
                                  --no-progress --quiet \
                                  --scanners vuln \
                                  --severity CRITICAL,HIGH \
                                  --format table .
                            '''
                        }
                    }
                }

                stage('SAST - SonarQube') {
                    steps {
                        script {
                            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                                withSonarQubeEnv("${SONARQUBE_ENV}") {
                                    sh '''
                                        set -eux
                                        JARPATH=$(cat "$WORKSPACE/.jarpath" 2>/dev/null || echo "")
                                        test -n "$JARPATH" && test -f "$JARPATH"
                                        test -d "$WORKSPACE/target/classes"

                                        docker run --rm \
                                          --network "$NETWORK_NAME" \
                                          --volumes-from jenkins \
                                          --add-host=host.docker.internal:host-gateway \
                                          -e SONAR_HOST_URL="http://host.docker.internal:9000" \
                                          -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                          -w "$WORKSPACE" \
                                          maven:3.9.9-eclipse-temurin-17 \
                                          sh -lc "mvn -B -f '$WORKSPACE/pom.xml' \
                                            -Dmaven.repo.local='$MAVEN_REPO' \
                                            org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \
                                            -DskipTests \
                                            -Dsonar.projectKey='$APP_NAME' \
                                            -Dsonar.host.url='http://host.docker.internal:9000' \
                                            -Dsonar.login='$SONAR_AUTH_TOKEN' \
                                            -Dsonar.java.binaries='target/classes' \
                                            -Dsonar.qualitygate.wait=false"
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('SBOM - CycloneDX') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                            sh '''
                                set -eux
                                docker run --rm \
                                  --volumes-from jenkins \
                                  -w "$WORKSPACE" \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  sh -lc "mvn -B -f '$WORKSPACE/pom.xml' -Dmaven.repo.local='$MAVEN_REPO' org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom -DoutputFormat=all"

                                test -f "$WORKSPACE/target/bom.xml" && cp -f "$WORKSPACE/target/bom.xml" "$WORKSPACE/reports/sbom/bom.xml"
                                test -f "$WORKSPACE/target/bom.json" && cp -f "$WORKSPACE/target/bom.json" "$WORKSPACE/reports/sbom/bom.json"
                                test -s reports/sbom/bom.json
                            '''
                        }
                    }
                }
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eux
                    docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true

                    docker run -d \
                      --name "$MYSQL_CONTAINER" \
                      --network "$NETWORK_NAME" \
                      -e MYSQL_ROOT_PASSWORD=root \
                      -e MYSQL_DATABASE=archivage_doc \
                      -e MYSQL_USER=archivage_user \
                      -e MYSQL_PASSWORD=archivage_pass \
                      mysql:8.0

                    READY=0
                    for i in $(seq 1 30); do
                      if docker run --rm --network "$NETWORK_NAME" mysql:8.0 \
                        mysqladmin ping -h"$MYSQL_CONTAINER" -uroot -proot --silent; then
                        READY=1
                        break
                      fi
                      echo "Waiting for MySQL ($i/30)..."
                      sleep 5
                    done

                    test "$READY" -eq 1
                    echo "MySQL pret. Pause 10s..."
                    sleep 10
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    set -eux
                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true

                    mkdir -p "$WORKSPACE/uploads"

                    docker run -d \
                      --name "$APP_CONTAINER" \
                      --network "$NETWORK_NAME" \
                      --restart on-failure:5 \
                      -v "$WORKSPACE/uploads:/app/uploads" \
                      -e SPRING_PROFILES_ACTIVE=docker \
                      -e SPRING_DATASOURCE_URL="jdbc:mysql://$MYSQL_CONTAINER:3306/archivage_doc?useUnicode=true&allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC" \
                      -e SPRING_DATASOURCE_USERNAME="archivage_user" \
                      -e SPRING_DATASOURCE_PASSWORD="archivage_pass" \
                      -e GITHUB_OAUTH_SECRET="test-secret" \
                      -e JWT_SECRET="***REMOVED***" \
                      "$DOCKER_IMAGE"

                    READY=0
                    for i in $(seq 1 30); do
                      CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                        -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)

                      if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then
                        READY=1
                        break
                      fi

                      echo "Waiting for app health ($i/30)..."
                      docker ps -a --filter "name=$APP_CONTAINER" --format 'table {{.Names}}\t{{.Status}}' || true
                      sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                      set +x
                      echo "============================================================"
                      echo "CRASH APPLICATIF DETECTE"
                      echo "============================================================"
                      docker logs "$APP_CONTAINER" --tail 200 || true
                      exit 1
                    fi
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        set -eux
                        mkdir -p "$WORKSPACE/reports/zap"
                        chmod 777 "$WORKSPACE/reports/zap"

                        docker run --rm \
                          --user root \
                          --network "$NETWORK_NAME" \
                          -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                          ghcr.io/zaproxy/zaproxy:stable \
                          zap-baseline.py \
                          -t "http://$APP_CONTAINER:$APP_PORT/" \
                          -J "zap-report.json" \
                          -a -j -I || true

                        chmod -R 777 "$WORKSPACE/reports/zap/" || true

                        test -s "$WORKSPACE/reports/zap/zap-report.json" \
                          || echo '{"site":[{"alerts":[]}]}' > "$WORKSPACE/reports/zap/zap-report.json"

                        docker run --rm \
                          --volumes-from jenkins \
                          -w "$WORKSPACE/reports/zap" \
                          python:3.12-alpine \
                          python zap_to_html.py

                        echo "=== Contenu reports/zap ==="
                        ls -lah "$WORKSPACE/reports/zap/"
                    '''
                }
            }
        }

        stage('Policy - OPA Gate') {
            steps {
                sh '''
                    set -eux

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      python:3.12-alpine \
                      python reports/opa/build_input.py

                    docker run --rm \
                      --volumes-from jenkins \
                      -w "$WORKSPACE" \
                      openpolicyagent/opa:latest \
                      eval \
                      --format raw \
                      --data "$WORKSPACE/policy/security-gate.rego" \
                      --input "$WORKSPACE/reports/opa/input.json" \
                      "data.security.allow" | tee "$WORKSPACE/reports/opa/opa-result.txt"

                    if ! grep -qx "true" "$WORKSPACE/reports/opa/opa-result.txt"; then
                        echo ""
                        echo "============================================================"
                        echo "  OPA SECURITY GATE : ECHEC"
                        echo "  Le pipeline est bloque. Consultez le resume ci-dessus."
                        echo "  Criteres de blocage :"
                        echo "    - Trivy CRITICAL > 0"
                        echo "    - Gitleaks secrets > 0"
                        echo "    - ZAP HIGH > 0"
                        echo "============================================================"
                        exit 1
                    fi

                    echo "OPA Security Gate : PASS"
                '''
            }
        }
    }

    post {
        always {
            recordIssues(
                enabledForFailure: true,
                aggregatingResults: true,
                tools: [
                    trivy(
                        pattern: 'reports/trivy/trivy-report.json',
                        reportEncoding: 'UTF-8'
                    )
                ]
            )

            publishHTML(target: [
                allowMissing         : true,
                alwaysLinkToLastBuild: true,
                keepAll              : true,
                reportDir            : 'reports/zap',
                reportFiles          : 'zap-report.html',
                reportName           : 'ZAP Web Report'
            ])

            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true, fingerprint: true

            sh '''
                docker rm -f "$APP_CONTAINER"   >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        failure {
            echo 'Pipeline FAILED - consulter les rapports archives et le resume OPA.'
        }

        unstable {
            echo 'Pipeline UNSTABLE - des scans ont detecte des problemes non bloquants (Gitleaks, Trivy HIGH, SonarQube).'
        }

        success {
            echo 'Pipeline SUCCESS - tous les security gates sont passes.'
        }
    }
}
