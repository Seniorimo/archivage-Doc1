#!/usr/bin/env python3
"""
Affiche un résumé des résultats Gitleaks dans la console Jenkins.
"""
import json
import sys
from pathlib import Path

def print_gitleaks_summary(report_path):
    """Affiche un résumé des résultats Gitleaks."""
    report_file = Path(report_path)
    
    if not report_file.exists() or report_file.stat().st_size == 0:
        print("=== GITLEAKS SUMMARY ===")
        print("Aucun rapport disponible")
        print("Findings: 0")
        return
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            findings = data
        else:
            findings = data.get('findings', [])
        
        print("=== GITLEAKS SUMMARY ===")
        print(f"Total findings: {len(findings)}")
        
        if findings:
            # Compter par sévérité
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\nPar sévérité:")
            for severity in sorted(severity_counts.keys(), reverse=True):
                print(f"  {severity}: {severity_counts[severity]}")
            
            # Afficher les 5 premiers
            print("\nTop 5 findings:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. {finding.get('description', 'N/A')}")
                print(f"     Fichier: {finding.get('file', 'N/A')}")
                print(f"     Règle: {finding.get('ruleID', 'N/A')}")
        else:
            print("Aucun secret détecté ✓")
            
    except Exception as e:
        print(f"Erreur lors de la lecture du rapport: {e}")
        print("Findings: 0")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python print_gitleaks_summary.py <report_path>")
        sys.exit(1)
    
    print_gitleaks_summary(sys.argv[1])
