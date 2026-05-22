from pathlib import Path
import sys
import tempfile
import shutil

META = """<meta http-equiv="Content-Security-Policy" content="default-src 'self' data: blob: https:; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:;">"""


def patch(path_str: str):
    p = Path(path_str)
    if not p.exists():
        print(f"[SKIP] Fichier absent : {p}")
        return
    html = p.read_text(encoding="utf-8", errors="ignore")
    if 'http-equiv="Content-Security-Policy"' in html or "http-equiv='Content-Security-Policy'" in html:
        print(f"[OK] CSP deja presente : {p}")
        return
    nl = chr(10)
    if "<head>" in html:
        html = html.replace("<head>", "<head>" + nl + "  " + META, 1)
    else:
        html = META + nl + html
    
    # Write to temp file first, then replace original
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.html') as tmp:
        tmp.write(html)
        tmp_path = Path(tmp.name)
    
    try:
        shutil.move(tmp_path, p)
        print(f"[OK] CSP ajoutee : {p}")
    except Exception as e:
        print(f"[ERROR] Impossible de remplacer {p}: {e}")
        tmp_path.unlink(missing_ok=True)


for target in sys.argv[1:]:
    patch(target)
