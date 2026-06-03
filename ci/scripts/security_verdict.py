#!/usr/bin/env python3
"""
Génère un verdict de sécurité basé sur les résultats des scans.
Utilisé par l'étape 'Security Verdict' du pipeline Jenkins.
"""
import json
from pathlib import Path

def main():
    """Lit les résultats OPA et génère un verdict."""
    input_file = Path("reports/opa/input.json")
    
    if not input_file.exists() or input_file.stat().st_size == 0:
        print("UNSTABLE: rapport OPA absent ou vide")
        return
    
    try:
        data = json.loads(input_file.read_text(encoding="utf-8"))
        
        scan_status = data.get("scan_status", {})
        missing_scans = [name for name, status in scan_status.items() if status != "ok"]
        
        has_findings = (
            len(data.get("gitleaks", [])) > 0 or
            data.get("trivy", {}).get("critical", 0) > 0 or
            data.get("trivy", {}).get("high", 0) > 0 or
            data.get("trivy", {}).get("medium", 0) > 0 or
            data.get("trivy", {}).get("low", 0) > 0 or
            data.get("zap", {}).get("high", 0) > 0 or
            data.get("zap", {}).get("medium", 0) > 0 or
            data.get("zap", {}).get("low", 0) > 0
        )
        
        if missing_scans:
            print("UNSTABLE: scans manquants -> " + ", ".join(missing_scans))
        elif has_findings:
            print(
                "UNSTABLE: findings détectés -> "
                + "gitleaks=" + str(len(data.get("gitleaks", [])))
                + ", trivy="
                + str(data.get("trivy", {}).get("critical", 0)) + "C/"
                + str(data.get("trivy", {}).get("high", 0)) + "H/"
                + str(data.get("trivy", {}).get("medium", 0)) + "M/"
                + str(data.get("trivy", {}).get("low", 0)) + "L"
                + ", zap="
                + str(data.get("zap", {}).get("high", 0)) + "H/"
                + str(data.get("zap", {}).get("medium", 0)) + "M/"
                + str(data.get("zap", {}).get("low", 0)) + "L"
            )
        else:
            print("SUCCESS: aucun finding détecté")
            
    except Exception as e:
        print(f"UNSTABLE: erreur lors de l'analyse: {e}")

if __name__ == "__main__":
    main()
