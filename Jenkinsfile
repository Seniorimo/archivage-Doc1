pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    parameters {
        booleanParam(name: 'RUN_SONAR', defaultValue: true, description: 'Lancer l’analyse SonarQube')
        booleanParam(name: 'FAIL_FAST', defaultValue: false, description: 'Bloquer avant le déploiement si une vulnérabilité critique ou un secret est détecté')
    }

    environment {
        APP_NAME        = 'archivage-Doc'
        APP_CONTAINER   = 'app-archivage'
        MYSQL_CONTAINER = 'mysql-archivage'
        NETWORK_NAME    = 'archivage-net'
        APP_PORT        = '8090'

        DOCKER_IMAGE    = "archivage-app:${BUILD_NUMBER}"
        MAVEN_CACHE     = "${WORKSPACE}/.m2"
        TRIVY_CACHE     = "${WORKSPACE}/.trivycache"

        REPORT_DIR      = 'reports'
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
                    set -eu

                    mkdir -p "$REPORT_DIR"/gitleaks "$REPORT_DIR"/trivy "$REPORT_DIR"/sbom "$REPORT_DIR"/zap "$REPORT_DIR"/opa
                    mkdir -p "$TRIVY_CACHE" "$MAVEN_CACHE" policy uploads

                    docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"

                    cat > policy/security-gate.rego <<'REGO'
package security

default allow := false

allow if {
    input.gitleaks.count == 0
    input.trivy.critical == 0
    input.zap.high == 0
}
REGO

                    cat > "$REPORT_DIR/opa/build_input.py" <<'PYEOF'
import json
from pathlib import Path

def load_json(path, default):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def trivy_counts(doc):
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in doc.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            s = str(v.get("Severity", "")).upper()
            if s in sev:
                sev[s] += 1
    return sev

def add_counts(a, b):
    return {k: a[k] + b[k] for k in a}

gitleaks = load_json("reports/gitleaks/gitleaks-report.json", [])
if not isinstance(gitleaks, list):
    gitleaks = []

trivy_fs = load_json("reports/trivy/trivy-fs.json", {"Results": []})
trivy_image = load_json("reports/trivy/trivy-image.json", {"Results": []})
zap = load_json("reports/zap/zap-report.json", {"site": [{"alerts": []}]})

sev = add_counts(trivy_counts(trivy_fs), trivy_counts(trivy_image))

zap_high = 0
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        if str(alert.get("riskcode", "")).strip() == "3":
            zap_high += 1

payload = {
    "gitleaks": {
        "count": len(gitleaks)
    },
    "trivy": {
        "critical": sev["CRITICAL"],
        "high": sev["HIGH"],
        "medium": sev["MEDIUM"],
        "low": sev["LOW"]
    },
    "zap": {
        "high": zap_high
    }
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

summary = f"""GITLEAKS_COUNT={payload['gitleaks']['count']}
TRIVY_CRITICAL={payload['trivy']['critical']}
TRIVY_HIGH={payload['trivy']['high']}
TRIVY_MEDIUM={payload['trivy']['medium']}
TRIVY_LOW={payload['trivy']['low']}
ZAP_HIGH={payload['zap']['high']}
"""
Path("reports/opa/summary.env").write_text(summary, encoding="utf-8")

print("=== OPA INPUT SUMMARY ===")
print(f"Gitleaks secrets : {payload['gitleaks']['count']}")
print(f"Trivy CRITICAL   : {payload['trivy']['critical']}")
print(f"Trivy HIGH       : {payload['trivy']['high']}")
print(f"Trivy MEDIUM     : {payload['trivy']['medium']}")
print(f"Trivy LOW        : {payload['trivy']['low']}")
print(f"ZAP HIGH         : {payload['zap']['high']}")
print("=========================")
PYEOF

                    cat > "$REPORT_DIR/zap/zap_to_html.py" <<'ZAPEOF'
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

counts = {"3": 0, "2": 0, "1": 0, "0": 0}
for a in all_alerts:
    rc = str(a.get("riskcode", "0"))
    if rc in counts:
        counts[rc] += 1

rows = ""
for a in all_alerts:
    rc   = str(a.get("riskcode", "0"))
    name = a.get("alert", a.get("name", "?"))
    desc = str(a.get("desc", ""))[:300].replace("<", "&lt;").replace(">", "&gt;")
    sol  = str(a.get("solution", ""))[:300].replace("<", "&lt;").replace(">", "&gt;")
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
  <tbody>{rows if rows else '<tr><td colspan="4" style="text-align:center;padding:30px;color:#27ae60"><strong>Aucune alerte détectée</strong></td></tr>'}</tbody>
</table>
</body>
</html>"""

out.write_text(html, encoding="utf-8")
print("Rapport HTML ZAP généré : " + str(out))
ZAPEOF

                    echo "Workspace préparé avec succès."
                '''
            }
        }

        stage('Build & Package') {
            steps {
                sh '''
                    set -eu

                    echo "=== BUILD & PACKAGE ==="

                    docker run --rm \
                      -v "$WORKSPACE":"$WORKSPACE" \
                      -w "$WORKSPACE" \
                      -v "$MAVEN_CACHE:/root/.m2" \
                      maven:3.9.9-eclipse-temurin-17 \
                      mvn -B clean package -DskipTests

                    JARPATH="$(find target -maxdepth 1 -type f -name "*.jar" ! -name "*.original" | head -n 1)"
                    test -n "$JARPATH"
                    echo "$JARPATH" > .jarpath

                    echo "JAR détecté : $JARPATH"

                    docker build -t "$DOCKER_IMAGE" .
                    echo "Image Docker construite : $DOCKER_IMAGE"
                '''
            }
        }

        stage('Security Scans') {
            parallel {
                stage('Gitleaks') {
                    steps {
                        sh '''
                            set -eu

                            docker run --rm \
                              -v "$WORKSPACE":"$WORKSPACE" \
                              -w "$WORKSPACE" \
                              zricethezav/gitleaks:latest \
                              detect \
                              --source . \
                              --report-format json \
                              --report-path reports/gitleaks/gitleaks-report.json \
                              --exit-code 0 \
                              --no-banner || true

                            test -s reports/gitleaks/gitleaks-report.json || echo '[]' > reports/gitleaks/gitleaks-report.json
                            echo "Rapport Gitleaks généré."
                        '''
                    }
                }

                stage('Trivy FS') {
                    steps {
                        sh '''
                            set -eu

                            docker run --rm \
                              -v "$WORKSPACE":"$WORKSPACE" \
                              -w "$WORKSPACE" \
                              -v "$TRIVY_CACHE:/root/.cache/trivy" \
                              ghcr.io/aquasecurity/trivy:latest \
                              fs \
                              --no-progress \
                              --scanners vuln \
                              --severity CRITICAL,HIGH,MEDIUM,LOW \
                              --format json \
                              --output reports/trivy/trivy-fs.json \
                              .

                            echo "Rapport Trivy FS généré."
                        '''
                    }
                }

                stage('Trivy Image') {
                    steps {
                        sh '''
                            set -eu

                            docker run --rm \
                              -v "$WORKSPACE":"$WORKSPACE" \
                              -w "$WORKSPACE" \
                              -v "$TRIVY_CACHE:/root/.cache/trivy" \
                              ghcr.io/aquasecurity/trivy:latest \
                              image \
                              --no-progress \
                              --scanners vuln \
                              --severity CRITICAL,HIGH,MEDIUM,LOW \
                              --format json \
                              --output reports/trivy/trivy-image.json \
                              "$DOCKER_IMAGE"

                            echo "Rapport Trivy Image généré."
                        '''
                    }
                }

                stage('SBOM - CycloneDX') {
                    steps {
                        sh '''
                            set -eu

                            docker run --rm \
                              -v "$WORKSPACE":"$WORKSPACE" \
                              -w "$WORKSPACE" \
                              -v "$MAVEN_CACHE:/root/.m2" \
                              maven:3.9.9-eclipse-temurin-17 \
                              mvn -B -DskipTests \
                              org.cyclonedx:cyclonedx-maven-plugin:2.7.11:makeAggregateBom \
                              -DoutputFormat=all

                            test -f target/bom.xml && cp -f target/bom.xml reports/sbom/bom.xml || true
                            test -f target/bom.json && cp -f target/bom.json reports/sbom/bom.json || true

                            echo "SBOM généré."
                        '''
                    }
                }

                stage('SonarQube') {
                    when {
                        expression { return params.RUN_SONAR }
                    }
                    steps {
                        withSonarQubeEnv("${SONARQUBE_ENV}") {
                            sh '''
                                set -eu

                                docker run --rm \
                                  -v "$WORKSPACE":"$WORKSPACE" \
                                  -w "$WORKSPACE" \
                                  -v "$MAVEN_CACHE:/root/.m2" \
                                  -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                                  -e SONAR_AUTH_TOKEN="$SONAR_AUTH_TOKEN" \
                                  maven:3.9.9-eclipse-temurin-17 \
                                  mvn -B sonar:sonar \
                                  -DskipTests \
                                  -Dsonar.projectKey="$APP_NAME" \
                                  -Dsonar.host.url="$SONAR_HOST_URL" \
                                  -Dsonar.token="$SONAR_AUTH_TOKEN" \
                                  -Dsonar.java.binaries=target/classes \
                                  -Dsonar.qualitygate.wait=false
                            '''
                        }
                    }
                }
            }
        }

        stage('Pre-Deploy Gate') {
            steps {
                sh '''
                    set -eu

                    echo "=== PRE-DEPLOY GATE ==="
                    docker run --rm \
                      -v "$WORKSPACE":"$WORKSPACE" \
                      -w "$WORKSPACE" \
                      python:3.12-alpine \
                      python reports/opa/build_input.py

                    . reports/opa/summary.env

                    echo "Résumé:"
                    echo "  Gitleaks  : $GITLEAKS_COUNT"
                    echo "  Trivy CRIT: $TRIVY_CRITICAL"
                    echo "  Trivy HIGH: $TRIVY_HIGH"
                    echo "  ZAP HIGH  : $ZAP_HIGH"

                    if [ "${FAIL_FAST:-false}" = "true" ]; then
                        if [ "$GITLEAKS_COUNT" -gt 0 ] || [ "$TRIVY_CRITICAL" -gt 0 ]; then
                            echo "Bloquage pré-déploiement activé : FAIL_FAST=true"
                            exit 1
                        fi
                    fi

                    if [ "$TRIVY_HIGH" -gt 0 ] || [ "$GITLEAKS_COUNT" -gt 0 ]; then
                        echo "Avertissement : findings détectés, mais le pipeline continue pour tester les autres briques."
                    fi
                '''
            }
        }

        stage('Deploy MySQL') {
            steps {
                sh '''
                    set -eu

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
                        if docker run --rm --network "$NETWORK_NAME" mysql:8.0 \
                            mysqladmin ping -h"$MYSQL_CONTAINER" -uroot -proot --silent; then
                            READY=1
                            break
                        fi
                        echo "Attente MySQL ($i/30)..."
                        sleep 5
                    done

                    test "$READY" -eq 1
                    echo "MySQL prêt."
                '''
            }
        }

        stage('Deploy App') {
            steps {
                sh '''
                    set -eu

                    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                    mkdir -p uploads

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
                      -e JWT_SECRET="test-secret-test-secret-test-secret-test-secret" \
                      "$DOCKER_IMAGE" >/dev/null

                    READY=0
                    for i in $(seq 1 30); do
                        CODE=$(docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.7.1 \
                            -s -o /dev/null -w "%{http_code}" "http://$APP_CONTAINER:$APP_PORT/actuator/health" || true)

                        if echo "$CODE" | grep -qE "200|301|302|401|403|404"; then
                            READY=1
                            echo "Application répond avec HTTP $CODE"
                            break
                        fi

                        echo "Attente application ($i/30)..."
                        docker logs "$APP_CONTAINER" --tail 50 || true
                        sleep 5
                    done

                    if [ "$READY" -ne 1 ]; then
                        echo "=============================="
                        echo "ERREUR : l'application ne répond pas"
                        echo "=============================="
                        docker logs "$APP_CONTAINER" --tail 200 || true
                        exit 1
                    fi
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                sh '''
                    set -eu

                    mkdir -p "$WORKSPACE/reports/zap"
                    chmod 777 "$WORKSPACE/reports/zap" || true

                    docker run --rm \
                      --network "$NETWORK_NAME" \
                      -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                      ghcr.io/zaproxy/zaproxy:stable \
                      zap-baseline.py \
                      -t "http://$APP_CONTAINER:$APP_PORT/" \
                      -J "zap-report.json" \
                      -a -j -I || true

                    test -s "$WORKSPACE/reports/zap/zap-report.json" || echo '{"site":[{"alerts":[]}]}' > "$WORKSPACE/reports/zap/zap-report.json"

                    docker run --rm \
                      -v "$WORKSPACE/reports/zap:/zap/wrk:rw" \
                      python:3.12-alpine \
                      python zap_to_html.py

                    echo "Rapport ZAP généré."
                '''
            }
        }

        stage('OPA Final Gate') {
            steps {
                sh '''
                    set -eu

                    echo "=== FINAL OPA GATE ==="
                    docker run --rm \
                      -v "$WORKSPACE":"$WORKSPACE" \
                      -w "$WORKSPACE" \
                      python:3.12-alpine \
                      python reports/opa/build_input.py

                    docker run --rm \
                      -v "$WORKSPACE":"$WORKSPACE" \
                      -w "$WORKSPACE" \
                      openpolicyagent/opa:latest \
                      eval \
                      --format raw \
                      --data policy/security-gate.rego \
                      --input reports/opa/input.json \
                      "data.security.allow" | tee reports/opa/opa-result.txt

                    if ! grep -qx "true" reports/opa/opa-result.txt; then
                        echo "OPA gate refusé."
                        echo "Critères bloquants:"
                        echo "  - Gitleaks secrets > 0"
                        echo "  - Trivy CRITICAL > 0"
                        echo "  - ZAP HIGH > 0"
                        exit 1
                    fi

                    echo "OPA gate validé."
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*,policy/**/*,.jarpath', allowEmptyArchive: true, fingerprint: true

            sh '''
                set +e
                docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
                docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
                docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
            '''
        }

        success {
            echo 'Pipeline SUCCESS'
        }

        unstable {
            echo 'Pipeline UNSTABLE'
        }

        failure {
            echo 'Pipeline FAILED'
        }
    }
}
