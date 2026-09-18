"""Fase 3.1 (PDF p.11): genera trafico NORMAL simulado via WAAP y lo guarda estructurado.
~200 peticiones variadas (busquedas, home, producto, login dummy, challenges, ordenamiento).
Cada fila: {url, body, headers, timestamp, ip}.
"""
import json
import os
import random
import time
import urllib.request
import urllib.parse

BASE = "http://localhost:8080"
OUT = "logs/access_normal.jsonl"
# Ritmo humano (PDF p.11: 15-20 min navegando => rpm bajo). Por defecto rapido;
# con PACE=humano se simulan ~15 min de navegacion manual (rpm 5-15).
N = int(os.environ.get("GEN_N", "200"))
PACE = os.environ.get("PACE", "rapido")
SLEEP = (4.0, 11.0) if PACE == "humano" else (0.05, 0.4)
random.seed(20260918)

UAS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
    "curl/7.81.0",
]
SEARCHES = ["apple", "juice", "berry", "banana", "mango", "orange", "melon",
            "carrot", "lemon", "grape", "apple juice", "smoothie", "cake", "tea"]
STATIC = ["/", "/#/search", "/#/login", "/#/basket", "/#/score-board",
          "/api/Challenges/", "/rest/admin/application-version"]
LOGINS = [("admin@juice-sh.op", "admin123"), ("jim@juice-sh.op", "ncc-1701"),
          ("bender@juice-sh.op", "OhG0d!"), ("alice@example.com", "s3cret!")]


def req(method, path, body=None, headers=None):
    url = BASE + path
    data = None
    h = {"User-Agent": random.choice(UAS), "Accept": "*/*"}
    if headers:
        h.update(headers)
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    ts = time.time()
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            code = resp.status
    except Exception as e:  # noqa: BLE001 - trafico best-effort
        code = getattr(e, "code", 0)
    return {"url": path, "body": json.dumps(body) if body is not None else "",
            "headers": h, "timestamp": ts, "ip": "127.0.0.1", "status": code}


def main():
    rows = []
    for i in range(N):
        pick = random.random()
        if pick < 0.45:
            q = random.choice(SEARCHES)
            extra = ""
            if random.random() < 0.25:
                extra = random.choice(["&sort=name", "&sort=price", "&page=2"])
            rows.append(req("GET", f"/rest/products/search?q={urllib.parse.quote(q)}{extra}"))
        elif pick < 0.65:
            rows.append(req("GET", random.choice(STATIC)))
        elif pick < 0.78:
            pid = random.randint(1, 35)
            rows.append(req("GET", f"/api/Products/{pid}"))
        elif pick < 0.90:
            u, p = random.choice(LOGINS)
            rows.append(req("POST", "/rest/user/login", {"email": u, "password": p}))
        else:
            rows.append(req("GET", "/rest/products/search?q=" + urllib.parse.quote(random.choice(SEARCHES)[: random.randint(1, 5)])))
        if (i + 1) % 50 == 0:
            print(f"{i + 1}/{N} ...")
        time.sleep(random.uniform(*SLEEP))
    ok = sum(1 for r in rows if r["status"] and r["status"] < 400)
    with open(OUT, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"OK: {len(rows)} filas -> {OUT} (2xx/3xx: {ok})")


if __name__ == "__main__":
    main()
