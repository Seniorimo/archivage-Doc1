import json
import os
from pathlib import Path

raw = Path("reports/gitleaks/gitleaks-raw.json")
out = Path("reports/gitleaks/gitleaks-report.json")

ignore_test_app_findings = os.environ.get("IGNORE_TEST_APP_FINDINGS", "false").lower() == "true"

# Test/demo paths to ignore.
IGNORED_PATHS = [
    "src/main/resources/application.properties",
    "Jenkinsfile",
]

# Test/demo rules to ignore only when the path matches.
IGNORED_RULES = {
    "Jenkinsfile": ["curl-auth-user"],
}

if not raw.exists() or raw.stat().st_size == 0:
    out.write_text("[]", encoding="utf-8")
    print("Aucun rapport brut Gitleaks, rapport final vide.")
    raise SystemExit(0)

data = json.loads(raw.read_text(encoding="utf-8"))
filtered = []

for item in data:
    rule = item.get("RuleID")
    path = item.get("File")

    if ignore_test_app_findings:
        if path in IGNORED_PATHS:
            continue
        if path in IGNORED_RULES and rule in IGNORED_RULES[path]:
            continue

    filtered.append(item)

ignored_count = len(data) - len(filtered)
out.write_text(json.dumps(filtered, indent=2), encoding="utf-8")
print(f"Gitleaks raw={len(data)} filtered={len(filtered)} ignored_test={ignored_count}")
