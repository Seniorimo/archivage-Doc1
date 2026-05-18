import json
import os
from pathlib import Path
from urllib.parse import urlparse

raw = Path("reports/zap/zap-report.json")
out = Path("reports/zap/zap-report.filtered.json")

ignore_test_app_findings = os.environ.get("IGNORE_TEST_APP_FINDINGS", "false").lower() == "true"

# Test/demo endpoint prefixes to ignore.
IGNORED_ENDPOINT_PREFIXES = [
    "/api/test/devsecops/",
]

# Test/demo specific paths to ignore.
IGNORED_PATHS = [
    "/api/test/devsecops/zap-demo",
    "/api/test/devsecops/cmd",
    "/api/test/devsecops/crypto",
    "/api/test/devsecops/path",
    "/api/test/devsecops/sqli",
    "/api/test/devsecops/assets/",
]

# Demo JS libraries to ignore only when under test/demo paths.
IGNORED_DEMO_ASSETS = [
    "angular-1.2.19.min.js",
    "bootstrap-3.3.7.min.js",
    "jquery-1.8.3.min.js",
]


def uri_path(uri):
    parsed = urlparse(uri or "")
    return parsed.path if parsed.scheme else (uri or "")


if not raw.exists() or raw.stat().st_size == 0:
    out.write_text(json.dumps({"site": [{"@name": "baseline-scan", "alerts": []}]}, indent=2), encoding="utf-8")
    print("Aucun rapport brut ZAP, rapport filtre vide.")
    raise SystemExit(0)

data = json.loads(raw.read_text(encoding="utf-8"))
filtered_alerts = []
total_instances = 0
kept_instances = 0

for site in data.get("site", []):
    for alert in site.get("alerts", []):
        instances = alert.get("instances", [])
        total_instances += len(instances)
        filtered_instances = []

        for instance in instances:
            uri = instance.get("uri", "")
            path = uri_path(uri)
            should_ignore = False

            if ignore_test_app_findings:
                if any(path.startswith(prefix) for prefix in IGNORED_ENDPOINT_PREFIXES):
                    should_ignore = True
                if any(path.startswith(path_prefix) for path_prefix in IGNORED_PATHS):
                    should_ignore = True
                if any(asset in path for asset in IGNORED_DEMO_ASSETS) and any(
                    prefix in path for prefix in IGNORED_ENDPOINT_PREFIXES
                ):
                    should_ignore = True

            if not should_ignore:
                filtered_instances.append(instance)

        if filtered_instances:
            alert_copy = alert.copy()
            alert_copy["instances"] = filtered_instances
            filtered_alerts.append(alert_copy)
            kept_instances += len(filtered_instances)

filtered_data = {"site": []}
for site in data.get("site", []):
    site_copy = site.copy()
    site_copy["alerts"] = filtered_alerts
    filtered_data["site"].append(site_copy)

ignored_count = total_instances - kept_instances
out.write_text(json.dumps(filtered_data, indent=2), encoding="utf-8")
print(f"ZAP instances raw={total_instances} kept={kept_instances} ignored_test={ignored_count}")
