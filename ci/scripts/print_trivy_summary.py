#!/usr/bin/env python3
"""
Affiche un résumé des résultats Trivy dans la console Jenkins.
"""
import json
import sys
from pathlib import Path

def print_trivy_summary(report_path):
    """Affiche un résumé des résultats Trivy."""
    report_file = Path(report_path)
    
    if not report_file.exists() or report_file.stat().st_size == 0:
        print("=== TRIVY SUMMARY ===")
        print("Aucun rapport disponible")
        print("Vulnerabilities: 0")
        return
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        results = data.get('Results', []) if isinstance(data, dict) else []
        
        for result in results:
            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                severity = (vuln.get('Severity') or 'UNKNOWN').upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts['UNKNOWN'] += 1
        
        total_vulns = sum(severity_counts.values())
        
        print("=== TRIVY SUMMARY ===")
        print(f"Total vulnerabilities: {total_vulns}")
        
        if total_vulns > 0:
            print("\nPar sévérité:")
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    symbol = "🔴" if severity in ["CRITICAL", "HIGH"] else "🟡" if severity == "MEDIUM" else "🟢"
                    print(f"  {symbol} {severity}: {count}")
        else:
            print("Aucune vulnérabilité détectée ✓")
            
    except Exception as e:
        print(f"Erreur lors de la lecture du rapport: {e}")
        print("Vulnerabilities: 0")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python print_trivy_summary.py <report_path>")
        sys.exit(1)
    
    print_trivy_summary(sys.argv[1])
