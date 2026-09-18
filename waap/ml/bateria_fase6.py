"""Fase 6: bateria comparativa por capas -> evidencias/fase6/matriz.csv
Capas: CRS (WAAP :8080), ML (score, umbral 0.0), RASP (fork :3000 login / middleware).
"""
import csv
import subprocess
import sys

sys.path.insert(0, "waap/ml")
from score_request import score_request

WAAP = "http://localhost:8080"
DIRECT = "http://localhost:3000"  # fork rasp-lab (RASP)
TH = 0.0


def get(url, params=None):
    """Devuelve (codigo, etiqueta de capa): CRS si el 403 trae HTML nginx,
    RASP si trae el JSON del fork (el CRS dejo pasar)."""
    cmd = ["curl", "-s", "-w", "\n%{http_code}", url]
    if params:
        cmd[1:1] = ["--get", "--data-urlencode", params]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    body, _, code = r.stdout.rpartition("\n")
    code = code.strip()
    if code == "403" and "Operacion bloqueada por RASP" in body:
        return ("EVADE", "BLOQUEA")
    if code == "403":
        return ("BLOQUEA", "-")
    return ("EVADE" if code == "200" else code, "EVADE" if code == "200" else code)


def post_login(base, email, password):
    import json
    import urllib.request
    data = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(base + "/rest/user/login", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return str(resp.status)
    except Exception as e:  # noqa: BLE001
        return str(getattr(e, "code", "ERR"))


PAYLOADS = [
    ("SQLi clasico ' OR '1'='1", "search", "q=' OR '1'='1", None),
    ("SQLi encoded", "search", "q=%27%20OR%20%271%27%3D%271", None),
    ("SQLi comentarios /**/", "search", "q='/ **/OR/**/1=1--", None),
    ("SQLi fragmentado 2 params", "frag", None, None),
    ("SQLi UNION login", "login", None, ("admin' UNION SELECT * FROM Users--", "x")),
    ("SQLi clasico login", "login", None, ("' OR 1=1--", "x")),
    ("XSS basico", "search", "q=<script>alert(1)</script>", None),
    ("XSS encoded", "search", "q=%3Cscript%3Ealert(1)%3C/script%3E", None),
    ("Traversal ../../etc/passwd", "search", "q=../../etc/passwd", None),
]

rows = []
for name, kind, param, login in PAYLOADS:
    if kind == "search":
        crs, rasp_auto = get(WAAP + "/rest/products/search", param)
        url = "/rest/products/search?" + param.split("=", 1)[1] if "=" in (param or "") else "/"
        ml = "SI" if score_request(url, "") < TH else "NO"
        mid = get(DIRECT + "/rest/products/search", param)
        rasp = rasp_auto if rasp_auto != "-" else ("EVADE" if mid[0] == "EVADE" else mid[0])
        rasp = "BLOQUEA" if rasp == "BLOQUEA" else ("EVADE" if rasp in ("EVADE", "200") else rasp)
    elif kind == "frag":
        r = subprocess.run(["curl", "-s", "-w", "\n%{http_code}",
                            WAAP + "/rest/products/search?q='%20&x=OR%201=1"],
                           capture_output=True, text=True, timeout=20)
        body, _, code = r.stdout.rpartition("\n")
        if code.strip() == "403" and "Operacion bloqueada por RASP" in body:
            crs, rasp = "EVADE", "BLOQUEA"
        else:
            crs, rasp = code.strip(), "-"
        ml = "SI" if score_request("/rest/products/search?q='", "") < TH else "NO"
    else:
        email, password = login
        crs = post_login(WAAP, email, password)
        crs = "BLOQUEA" if crs == "403" else ("EVADE" if crs in ("200", "401") else crs)
        ml = "SI" if score_request("/rest/user/login", '{"email":"%s"}' % email) < TH else "NO"
        direct = post_login(DIRECT, email, password)
        rasp = "BLOQUEA" if direct == "403" else ("EVADE" if direct in ("200", "401") else direct)
    rows.append([name, crs, ml, rasp])
    print(f"{name:32} | CRS:{crs:>7} | ML:{ml:>3} | RASP:{rasp}")

with open("evidencias/fase6/matriz.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["Payload / tecnica", "Bloqueado por reglas (Fase 2)",
                "Detectado por IA/ML (Fase 3)", "Bloqueado por RASP (Fase 4)"])
    w.writerows(rows)
print("OK evidencias/fase6/matriz.csv")
