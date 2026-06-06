#!/usr/bin/env python3
"""
Affiche un résumé des résultats ZAP dans la console Jenkins.
"""
import json
import sys
from pathlib import Path

def print_zap_summary(report_path):
    """Affiche un résumé des résultats ZAP."""
    report_file = Path(report_path)
    
    if not report_file.exists() or report_file.stat().st_size == 0:
        print("=== ZAP SUMMARY ===")
        print("Aucun rapport disponible")
        print("Alerts: 0")
        return
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print("=== ZAP SUMMARY ===")
        
        sites = data.get('site', []) if isinstance(data, dict) else []
        
        risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        total_alerts = 0
        
        for site in sites:
            alerts = site.get('alerts', [])
            total_alerts += len(alerts)
            
            for alert in alerts:
                riskcode = alert.get('riskcode', '0')
                if riskcode == '3':
                    risk_counts["High"] += 1
                elif riskcode == '2':
                    risk_counts["Medium"] += 1
                elif riskcode == '1':
                    risk_counts["Low"] += 1
                else:
                    risk_counts["Informational"] += 1
        
        print(f"Total alerts: {total_alerts}")
        
        if total_alerts > 0:
            print("\nPar risque:")
            for risk, count in risk_counts.items():
                if count > 0:
                    symbol = "🔴" if risk == "High" else "🟡" if risk == "Medium" else "🟢"
                    print(f"  {symbol} {risk}: {count}")
            
            # Afficher les 5 premières alertes
            print("\nTop 5 alertes:")
            alert_count = 0
            for site in sites:
                for alert in site.get('alerts', []):
                    if alert_count >= 5:
                        break
                    alert_count += 1
                    print(f"  {alert_count}. {alert.get('name', 'N/A')}")
                    print(f"     Risque: {alert.get('riskdesc', 'N/A')}")
        else:
            print("Aucune alerte de sécurité détectée ✓")
            
    except Exception as e:
        print(f"Erreur lors de la lecture du rapport: {e}")
        print("Alerts: 0")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python print_zap_summary.py <report_path>")
        sys.exit(1)
    
    print_zap_summary(sys.argv[1])
