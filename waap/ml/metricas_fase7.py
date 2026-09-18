"""Fase 7 (PDF p.16): centraliza eventos, metricas por capa y MTTD simulado."""
import csv
import json
import subprocess
import sys
import time

sys.path.insert(0, "waap/ml")
from score_request import score_request

EV = "logs/eventos.jsonl"
events = []
now = time.time()


def emit(layer, verdict, detail, t=None):
    events.append({"ts": t or time.time(), "layer": layer,
                   "verdict": verdict, "detail": detail})


# 1. Reglas: barrido real midiendo tiempo-a-403 (MTTD por capa)
PAYLOADS = {
    "sqli-clasico": ("http://localhost:8080/rest/products/search", "q=' OR '1'='1"),
    "sqli-frag": None,  # se mide aparte (pasa CRS)
    "xss": ("http://localhost:8080/rest/products/search", "q=<script>alert(1)</script>"),
}
mttd = {}
for name, spec in PAYLOADS.items():
    if spec is None:
        continue
    url, param = spec
    t0 = time.time()
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "--get", "--data-urlencode", param, url],
                       capture_output=True, text=True, timeout=20)
    dt = (time.time() - t0) * 1000
    mttd[f"CRS/{name}"] = round(dt, 1)
    emit("reglas", "bloqueado" if r.stdout.strip() == "403" else "permitido", name, t0)

# RASP directo (fork :3000)
t0 = time.time()
r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
                    "http://localhost:3000/rest/user/login", "-H", "Content-Type: application/json",
                    "-d", '{"email":"\u0027 OR 1=1--","password":"x"}'],
                   capture_output=True, text=True, timeout=20)
mttd["RASP/sqli-login"] = round((time.time() - t0) * 1000, 1)
emit("rasp", "bloqueado" if r.stdout.strip() == "403" else "permitido", "sqli-login", t0)

# 2. ML: scores como eventos
for label, url, body, is_attack in [
    ("normal-busqueda", "/rest/products/search?q=apple", "", False),
    ("normal-login", "/rest/user/login", '{"email":"jim@juice-sh.op"}', False),
    ("atk-sqli", "/rest/products/search?q=' OR '1'='1", "", True),
    ("atk-frag", "/rest/products/search?q='", "", True),
    ("atk-xss", "/rest/products/search?q=<script>alert(1)</script>", "", True),
]:
    s = score_request(url, body)
    emit("ml", "anomalo" if s < 0.0 else "normal", f"{label} score={s:+.4f}")

with open(EV, "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

# 3. Metricas desde matrices (bateria 9 ataques; normales: 5 de Fase 3).
# reglas: 7/9 (evaden: fragmentado y comentarios-con-espacios).
# ml@0.0: 9/9 deteccion, FP=4/5 (TN=1) — senal, no gate.
# rasp (alcance SQL: 6 payloads SQL de la bateria): bloquea 4
#   (comentarios, fragmentado, UNION-login, clasico-login);
#   evaden 2 (clasico/encoded en search: hueco string-form). XSS/traversal: N/A.
metrics = [
    ("reglas CRS PL1", 7, 2, 0, 5),
    ("IA/ML umbral 0.0", 9, 0, 4, 1),
    ("RASP fork (SQL)", 4, 2, 0, 5),
]
print("capa               |  TPR   FPR   FNR")
for name, tp, fn, fp, tn in metrics:
    print(f"{name:18} | {tp/(tp+fn):.0%}  {fp/(fp+tn):.0%}  {fn/(tp+fn):.0%}   "
          f"(TP={tp} FN={fn} FP={fp} TN={tn})")
print("\nMTTD simulado (tiempo-a-veredicto por capa):")
for k, v in mttd.items():
    print(f"  {k}: {v} ms")
print(f"\nOK {EV} ({len(events)} eventos)")
