from pathlib import Path
import sys

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
    p.write_text(html, encoding="utf-8")
    print(f"[OK] CSP ajoutee : {p}")


for target in sys.argv[1:]:
    patch(target)
