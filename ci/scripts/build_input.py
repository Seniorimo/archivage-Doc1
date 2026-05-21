import json
import os
import time
import base64
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError


def load_json(path_str, default):
    p = Path(path_str)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


ignore_test_app_findings = os.environ.get("IGNORE_TEST_APP_FINDINGS", "false").lower() == "true"

scan_status = {
    "gitleaks": "missing",
    "trivy": "missing",
    "zap": "missing",
}

gitleaks_path = "reports/gitleaks/gitleaks-report.json"
zap_path = "reports/zap/zap-report.json"

if ignore_test_app_findings:
    zap_filtered = load_json("reports/zap/zap-report.filtered.json", None)
    if zap_filtered is not None:
        zap_path = "reports/zap/zap-report.filtered.json"

gitleaks = load_json(gitleaks_path, None)
if isinstance(gitleaks, list):
    scan_status["gitleaks"] = "ok"
else:
    gitleaks = []

trivy = load_json("reports/trivy/trivy-report.json", None)
if isinstance(trivy, dict) and isinstance(trivy.get("Results", []), list):
    scan_status["trivy"] = "ok"
else:
    trivy = {"Results": []}

zap = load_json(zap_path, None)
if isinstance(zap, dict) and isinstance(zap.get("site", []), list):
    scan_status["zap"] = "ok"
else:
    zap = {"site": [{"alerts": []}]}

sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in trivy.get("Results", []) or []:
    for v in result.get("Vulnerabilities", []) or []:
        s = (v.get("Severity") or "").upper()
        if s in sev:
            sev[s] += 1

zap_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
for site in zap.get("site", []) or []:
    for alert in site.get("alerts", []) or []:
        rc = str(alert.get("riskcode", "0"))
        if rc == "3":
            zap_counts["high"] += 1
        elif rc == "2":
            zap_counts["medium"] += 1
        elif rc == "1":
            zap_counts["low"] += 1
        else:
            zap_counts["info"] += 1

def fetch_sonarqube_with_retry(sonar_url: str, sonar_token: str, project_key: str, max_attempts: int = 10, delay: int = 6) -> dict | None:
    """Query SonarQube API with retry loop to wait for quality gate processing."""
    if not sonar_url or not project_key:
        return None

    credentials = base64.b64encode(f"{sonar_token}:".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}

    for attempt in range(max_attempts):
        try:
            # Check quality gate status
            req = Request(
                f"{sonar_url.rstrip('/')}/api/qualitygates/project_status?projectKey={project_key}",
                headers=headers
            )
            with urlopen(req, timeout=10) as r:
                gate_data = json.loads(r.read().decode())

            project_status = gate_data.get("projectStatus", {})
            if project_status.get("status"):
                # Quality gate is ready, fetch metrics too
                try:
                    metrics_req = Request(
                        f"{sonar_url.rstrip('/')}/api/measures/component?component={project_key}"
                        "&metricKeys=bugs,vulnerabilities,code_smells",
                        headers=headers
                    )
                    with urlopen(metrics_req, timeout=10) as r:
                        metrics_data = json.loads(r.read().decode())

                    metrics = {}
                    for m in metrics_data.get("component", {}).get("measures", []):
                        metrics[m["metric"]] = m.get("value", "0")

                    return {
                        "status": "ok",
                        "quality_gate": project_status.get("status", "NONE"),
                        "bugs": int(metrics.get("bugs", 0) or 0),
                        "vulnerabilities": int(metrics.get("vulnerabilities", 0) or 0),
                        "code_smells": int(metrics.get("code_smells", 0) or 0),
                    }
                except Exception:
                    # If metrics fail, still return quality gate status
                    return {
                        "status": "ok",
                        "quality_gate": project_status.get("status", "NONE"),
                        "bugs": 0,
                        "vulnerabilities": 0,
                        "code_smells": 0,
                    }
        except URLError as e:
            print(f"[INFO] SonarQube not ready (attempt {attempt + 1}/{max_attempts}): {e}")
        except Exception as e:
            print(f"[INFO] SonarQube check failed (attempt {attempt + 1}/{max_attempts}): {e}")

        if attempt < max_attempts - 1:
            time.sleep(delay)

    return None


# Try to get SonarQube data from API with retry (handles timing issue)
sonar_url = os.environ.get("SONAR_HOST_URL", "")
sonar_token = os.environ.get("SONAR_AUTH_TOKEN", "")
project_key = os.environ.get("APP_NAME", "archivage-Doc")

sonarqube_data = fetch_sonarqube_with_retry(sonar_url, sonar_token, project_key)

if sonarqube_data:
    sonarqube = sonarqube_data
    scan_status["sonar"] = "ok"
else:
    # Fallback to file-based check if API is unavailable
    sonar_summary = load_json("reports/sonar/sonar-summary.json", None)
    if isinstance(sonar_summary, dict):
        sonarqube = {
            "status": "ok",
            "quality_gate": sonar_summary.get("quality_gate", sonar_summary.get("qualityGate", "NONE")),
            "bugs": int(sonar_summary.get("bugs", 0) or 0),
            "vulnerabilities": int(sonar_summary.get("vulnerabilities", 0) or 0),
            "code_smells": int(sonar_summary.get("code_smells", sonar_summary.get("codeSmells", 0)) or 0),
        }
        scan_status["sonar"] = "ok"
    else:
        sonarqube = {
            "status": "missing",
            "quality_gate": "NONE",
            "bugs": 0,
            "vulnerabilities": 0,
            "code_smells": 0,
        }

payload = {
    "settings": {
        "enforce_gate": os.environ.get("ENFORCE_SECURITY_GATE", "false").lower() == "true",
    },
    "scan_status": scan_status,
    "gitleaks": gitleaks,
    "trivy": {
        "critical": sev["CRITICAL"],
        "high": sev["HIGH"],
        "medium": sev["MEDIUM"],
        "low": sev["LOW"],
    },
    "zap": zap_counts,
    "sonarqube": sonarqube,
}

Path("reports/opa").mkdir(parents=True, exist_ok=True)
Path("reports/opa/input.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

print("=== OPA INPUT SUMMARY ===")
print("scan_status        :", scan_status)
print("enforce_gate       :", payload["settings"]["enforce_gate"])
print("gitleaks findings  :", len(gitleaks))
print("trivy critical     :", sev["CRITICAL"])
print("trivy high         :", sev["HIGH"])
print("trivy medium       :", sev["MEDIUM"])
print("trivy low          :", sev["LOW"])
print("zap high           :", zap_counts["high"])
print("zap medium         :", zap_counts["medium"])
print("zap low            :", zap_counts["low"])
print("zap info           :", zap_counts["info"])
print("sonar status       :", sonarqube["status"])
print("sonar quality gate :", sonarqube["quality_gate"])
