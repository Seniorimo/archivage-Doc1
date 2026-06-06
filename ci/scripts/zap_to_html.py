#!/usr/bin/env python3
"""
Convertit le rapport JSON ZAP en HTML si nécessaire.
Si le fichier HTML existe déjà, ne fait rien.
"""
import json
import sys
from pathlib import Path

def zap_to_html():
    """Vérifie si le HTML ZAP existe, sinon crée un fichier HTML basique."""
    json_path = Path("zap-report.json")
    html_path = Path("zap-report.html")
    
    if html_path.exists() and html_path.stat().st_size > 0:
        print("ZAP HTML existe déjà, conversion non nécessaire")
        return
    
    if not json_path.exists() or json_path.stat().st_size == 0:
        # Créer un HTML vide
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>ZAP Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; margin-bottom: 20px; }
        .no-alerts { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP ZAP Security Report</h1>
        <p>Aucun rapport JSON disponible</p>
    </div>
    <div class="content">
        <p class="no-alerts">Aucune alerte ZAP détectée</p>
    </div>
</body>
</html>"""
        html_path.write_text(html_content, encoding='utf-8')
        print("Créé un HTML vide (pas de rapport JSON)")
        return
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        sites = data.get('site', []) if isinstance(data, dict) else []
        
        # Compter les alertes
        total_alerts = 0
        for site in sites:
            total_alerts += len(site.get('alerts', []))
        
        # Créer un HTML basique
        if total_alerts == 0:
            html_content = """<!DOCTYPE html>
<html>
<head>
    <title>ZAP Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; margin-bottom: 20px; }
        .no-alerts { color: green; font-weight: bold; font-size: 18px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP ZAP Security Report</h1>
    </div>
    <div class="content">
        <p class="no-alerts">✓ Aucune alerte de sécurité détectée</p>
        <p>Le scan ZAP n'a trouvé aucune vulnérabilité.</p>
    </div>
</body>
</html>"""
        else:
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ZAP Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f5f5f5; padding: 20px; margin-bottom: 20px; }}
        .alert {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
        .high {{ border-left: 5px solid #d9534f; }}
        .medium {{ border-left: 5px solid #f0ad4e; }}
        .low {{ border-left: 5px solid #5bc0de; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP ZAP Security Report</h1>
        <p>Total alerts: {total_alerts}</p>
    </div>
    <div class="content">
        <p>Le rapport JSON détaillé est disponible dans zap-report.json</p>
        <p>Utilisez le rapport HTML généré par ZAP pour plus de détails.</p>
    </div>
</body>
</html>"""
        
        html_path.write_text(html_content, encoding='utf-8')
        print(f"HTML ZAP créé: {total_alerts} alertes")
        
    except Exception as e:
        print(f"Erreur lors de la conversion: {e}")
        # Créer un HTML d'erreur
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ZAP Security Report</title>
</head>
<body>
    <h1>OWASP ZAP Security Report</h1>
    <p>Erreur lors de la conversion: {e}</p>
</body>
</html>"""
        html_path.write_text(html_content, encoding='utf-8')

if __name__ == "__main__":
    zap_to_html()
