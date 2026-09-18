"""Fase 3 (PDF p.12): matriz 10 peticiones, 2 umbrales y test de rafaga bot."""
import sys

sys.path.insert(0, "waap/ml")
from score_request import score_request

NORMAL = [
    ("busqueda comun", "/rest/products/search?q=apple", ""),
    ("login valido", "/rest/user/login", '{"email": "jim@juice-sh.op", "password": "ncc-1701"}'),
    ("home", "/", ""),
    ("producto", "/api/Products/1", ""),
    ("score-board", "/#/score-board", ""),
]
ATTACK = [
    ("SQLi clasico", "/rest/products/search?q=' OR '1'='1", ""),
    ("SQLi encoded (Fase 2)", "/rest/products/search?q=%27%20OR%20%271%27%3D%271", ""),
    ("SQLi comentarios", "/rest/products/search?q='/ **/OR/**/1=1--", ""),
    ("evasion fragmentada (Fase 2)", "/rest/products/search?q='", ""),
    ("XSS reflejado", "/rest/products/search?q=<script>alert(1)</script>", ""),
]

THRESHOLDS = [-0.05, 0.0]


def main():
    print(f"{'etiqueta':28} {'score':>10}  {'<-0.05':>7} {'<0.0':>6}  esperado")
    for th in THRESHOLDS:
        pass
    for name, url, body in NORMAL + ATTACK:
        s = score_request(url, body)
        flags = ["ANOMALO" if s < t else "normal " for t in THRESHOLDS]
        exp = "ataque " if (name, url, body) in [(n, u, b) for n, u, b in ATTACK] else "normal "
        print(f"{name:28} {s:10.4f}  {flags[0]:>7} {flags[1]:>6}  {exp}")
    print("\n--- Rafaga bot: 20 consultas rapidas (req_per_minute alto) ---")
    for rpm in (5, 30, 120):
        s = score_request("/rest/products/search?q=apple", "", req_per_minute=rpm)
        print(f"req_per_minute={rpm:4}: score={s:+.4f}  anomalo(<-0.05)={s < -0.05}")


if __name__ == "__main__":
    main()
