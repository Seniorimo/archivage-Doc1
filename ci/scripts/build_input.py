import json
import os
import time
import base64
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

TRIVY_REPORT_PATH = "reports/trivy/trivy-report.json"
ZAP_REPORT_PATH = "reports/zap/zap-report.filtered.json"
GITLEAKS_REPORT_PATH = "reports/gitleaks/gitleaks-report.json"
OUTPUT_PATH = "reports/opa/input.json"


def load_json(path_str, default):
    p = Path(path_str)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def parse_enforce_gate() -> bool:
    return os.environ.get("ENFORCE_GATE", "false").strip().lower() == "true"


def count_trivy_vulnerabilities(report_path: str) -> dict:
    """Extract Trivy severity counts; default all counts to 0 when the report is missing."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    data = load_json(report_path, None)
    if not isinstance(data, dict):
        return counts

    for result in data.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            severity = (vuln.get("Severity") or "").upper()
            if severity == "CRITICAL":
                counts["critical"] += 1
            elif severity == "HIGH":
                counts["high"] += 1
            elif severity == "MEDIUM":
                counts["medium"] += 1
            elif severity == "LOW":
                counts["low"] += 1

    return counts


def count_zap_alerts(report_path: str) -> dict:
    """Extract ZAP alert counts from the filtered report; default all counts to 0 when missing."""
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    data = load_json(report_path, None)
    if not isinstance(data, dict):
        return counts

    for site in data.get("site", []) or []:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue
            risk_code = str(alert.get("riskcode", "0"))
            if risk_code == "3":
                counts["high"] += 1
            elif risk_code == "2":
                counts["medium"] += 1
            elif risk_code == "1":
                counts["low"] += 1
            else:
                counts["info"] += 1

    return counts


def load_gitleaks_findings(report_path: str) -> list:
    data = load_json(report_path, None)
    if isinstance(data, list):
        return data
    return []


def fetch_sonarqube_with_retry(
    sonar_url: str, sonar_token: str, project_key: str, max_attempts: int = 10, delay: int = 6
) -> dict | None:
    """Query SonarQube API with retry loop to wait for quality gate processing."""
    if not sonar_url or not project_key:
        return None

    credentials = base64.b64encode(f"{sonar_token}:".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}

    for attempt in range(max_attempts):
        try:
            req = Request(
                f"{sonar_url.rstrip('/')}/api/qualitygates/project_status?projectKey={project_key}",
                headers=headers,
            )
            with urlopen(req, timeout=10) as response:
                gate_data = json.loads(response.read().decode())

            project_status = gate_data.get("projectStatus", {})
            if project_status.get("status"):
                try:
                    metrics_req = Request(
                        f"{sonar_url.rstrip('/')}/api/measures/component?component={project_key}"
                        "&metricKeys=bugs,vulnerabilities,code_smells",
                        headers=headers,
                    )
                    with urlopen(metrics_req, timeout=10) as response:
                        metrics_data = json.loads(response.read().decode())

                    metrics = {}
                    for measure in metrics_data.get("component", {}).get("measures", []):
                        metrics[measure["metric"]] = measure.get("value", "0")

                    return {
                        "status": "ok",
                        "quality_gate": project_status.get("status", "NONE"),
                        "bugs": int(metrics.get("bugs", 0) or 0),
                        "vulnerabilities": int(metrics.get("vulnerabilities", 0) or 0),
                        "code_smells": int(metrics.get("code_smells", 0) or 0),
                    }
                except Exception:
                    return {
                        "status": "ok",
                        "quality_gate": project_status.get("status", "NONE"),
                        "bugs": 0,
                        "vulnerabilities": 0,
                        "code_smells": 0,
                    }
        except URLError as exc:
            print(f"[INFO] SonarQube not ready (attempt {attempt + 1}/{max_attempts}): {exc}")
        except Exception as exc:
            print(f"[INFO] SonarQube check failed (attempt {attempt + 1}/{max_attempts}): {exc}")

        if attempt < max_attempts - 1:
            time.sleep(delay)

    return None


def load_sonarqube_data() -> dict:
    sonar_url = os.environ.get("SONAR_HOST_URL", "")
    sonar_token = os.environ.get("SONAR_AUTH_TOKEN", "")
    project_key = os.environ.get("APP_NAME", "archivage-Doc")

    sonarqube_data = fetch_sonarqube_with_retry(sonar_url, sonar_token, project_key)
    if sonarqube_data:
        return sonarqube_data

    sonar_summary = load_json("reports/sonar/sonar-summary.json", None)
    if isinstance(sonar_summary, dict):
        return {
            "status": "ok",
            "quality_gate": sonar_summary.get("quality_gate", sonar_summary.get("qualityGate", "NONE")),
            "bugs": int(sonar_summary.get("bugs", 0) or 0),
            "vulnerabilities": int(sonar_summary.get("vulnerabilities", 0) or 0),
            "code_smells": int(sonar_summary.get("code_smells", sonar_summary.get("codeSmells", 0)) or 0),
        }

    return {
        "status": "missing",
        "quality_gate": "NONE",
        "bugs": 0,
        "vulnerabilities": 0,
        "code_smells": 0,
    }


def build_payload() -> dict:
    enforce_gate = parse_enforce_gate()
    trivy_counts = count_trivy_vulnerabilities(TRIVY_REPORT_PATH)
    zap_counts = count_zap_alerts(ZAP_REPORT_PATH)
    gitleaks = load_gitleaks_findings(GITLEAKS_REPORT_PATH)
    sonarqube = load_sonarqube_data()

    return {
        "enforce_gate": enforce_gate,
        "trivy": trivy_counts,
        "zap": zap_counts,
        "gitleaks": gitleaks,
        "sonarqube": sonarqube,
    }


def main() -> None:
    payload = build_payload()

    Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_PATH).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("=== OPA INPUT SUMMARY ===")
    print("enforce_gate       :", payload["enforce_gate"])
    print("trivy critical     :", payload["trivy"]["critical"])
    print("trivy high         :", payload["trivy"]["high"])
    print("trivy medium       :", payload["trivy"]["medium"])
    print("trivy low          :", payload["trivy"]["low"])
    print("zap high           :", payload["zap"]["high"])
    print("zap medium         :", payload["zap"]["medium"])
    print("zap low            :", payload["zap"]["low"])
    print("zap info           :", payload["zap"]["info"])
    print("gitleaks findings  :", len(payload["gitleaks"]))
    print("sonar status       :", payload["sonarqube"]["status"])
    print("sonar quality gate :", payload["sonarqube"]["quality_gate"])


if __name__ == "__main__":
    main()
