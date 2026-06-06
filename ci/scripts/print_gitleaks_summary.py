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
        
        # Gitleaks v8 JSON is a flat list of findings with PascalCase keys:
        # RuleID, Description, File, StartLine, EndLine, StartColumn, EndColumn,
        # Match, Secret, Commit, Author, Email, Date, Message, Tags, Entropy, Fingerprint.
        # There is no "severity" field in the native gitleaks schema; classification
        # is done downstream by OWASP/SAST tooling, not by gitleaks itself.
        if isinstance(data, list):
            findings = data
        else:
            findings = data.get('findings', [])

        print("=== GITLEAKS SUMMARY ===")
        print(f"Total findings: {len(findings)}")

        if findings:
            # Compter par règle (proxy de sévérité dans le format gitleaks natif).
            rule_counts: dict[str, int] = {}
            for finding in findings:
                rule_id = finding.get('RuleID', 'UNKNOWN')
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

            print("\nPar règle (trié par fréquence):")
            for rule_id, count in sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True):
                print(f"  {rule_id}: {count}")

            # Afficher les 5 premiers findings avec les clés PascalCase correctes.
            print("\nTop 5 findings:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. {finding.get('Description', 'N/A')}")
                print(f"     Rule    : {finding.get('RuleID', 'N/A')}")
                print(f"     File    : {finding.get('File', 'N/A')}")
                print(f"     Line    : {finding.get('StartLine', '?')}")
                secret = finding.get('Secret', '') or ''
                if secret:
                    snippet = secret.replace('\n', '\\n')[:60]
                    print(f"     Secret  : {snippet}{'...' if len(secret) > 60 else ''}")
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
