#!/usr/bin/env python3
"""
Affiche un résumé des résultats SonarQube dans la console Jenkins.
"""
import json
import sys
from pathlib import Path

def print_sonar_summary(report_path):
    """Affiche un résumé des résultats SonarQube."""
    report_file = Path(report_path)
    
    if not report_file.exists() or report_file.stat().st_size == 0:
        print("=== SONARQUBE SUMMARY ===")
        print("Aucun rapport disponible")
        return
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print("=== SONARQUBE SUMMARY ===")
        
        # Format API issues/search
        if 'issues' in data:
            issues = data.get('issues', [])
            total = data.get('total', len(issues))
            
            print(f"Total issues: {total}")
            
            if total > 0:
                # Compter par sévérité
                severity_counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
                for issue in issues:
                    severity = issue.get('severity', 'INFO').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                print("\nPar sévérité:")
                for severity in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        symbol = "🔴" if severity in ["BLOCKER", "CRITICAL"] else "🟡" if severity == "MAJOR" else "🟢"
                        print(f"  {symbol} {severity}: {count}")
                
                # Afficher les 5 premiers
                print("\nTop 5 issues:")
                for i, issue in enumerate(issues[:5], 1):
                    print(f"  {i}. {issue.get('rule', 'N/A')}")
                    print(f"     Message: {issue.get('message', 'N/A')[:80]}")
            else:
                print("Aucun issue détectée ✓")
        
        # Format quality gate status
        elif 'projectStatus' in data or 'quality_gate' in data:
            status = data.get('projectStatus', {}).get('status', data.get('quality_gate', 'UNKNOWN'))
            print(f"Quality Gate: {status}")
            
            if 'component' in data:
                measures = data.get('component', {}).get('measures', [])
                print("\nMétriques:")
                for measure in measures:
                    metric = measure.get('metric', 'N/A')
                    value = measure.get('value', 'N/A')
                    print(f"  {metric}: {value}")
                    
    except Exception as e:
        print(f"Erreur lors de la lecture du rapport: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python print_sonar_summary.py <report_path>")
        sys.exit(1)
    
    print_sonar_summary(sys.argv[1])
