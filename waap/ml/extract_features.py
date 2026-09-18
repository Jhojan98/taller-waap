"""Fase 3.2 (PDF p.11): extraccion de caracteristicas de un log de acceso."""
import json
import math
import re

import pandas as pd

SUSPICIOUS = re.compile(r"(--|;|<script|\.\./|\bUNION\b|\bOR\b\s+1=1)", re.I)


def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(pr * math.log2(pr) for pr in probs)


def extract(request_row):
    url = request_row["url"]
    body = request_row.get("body", "")
    return {
        "url_length": len(url),
        "body_length": len(body),
        "entropy": shannon_entropy(url + body),
        "n_params": url.count("&") + 1 if "?" in url else 0,
        "has_suspicious_chars": bool(SUSPICIOUS.search(url + body)),
        "req_per_minute": request_row.get("req_per_minute", 0),
    }


def main(in_path="logs/access_normal.jsonl", out_path="logs/features_normal_traffic.csv"):
    rows = [json.loads(line) for line in open(in_path)]
    # req_per_minute: ventana deslizante 60s por IP
    rows.sort(key=lambda r: r["timestamp"])
    counts = {}
    for r in rows:
        ip = r.get("ip", "?")
        ts = r["timestamp"]
        window = [t for t in counts.get(ip, []) if ts - t < 60]
        window.append(ts)
        counts[ip] = window
        r["req_per_minute"] = len(window)
    feats = [extract(r) for r in rows]
    df = pd.DataFrame(feats)
    df.to_csv(out_path, index=False)
    print(f"OK: {len(df)} filas -> {out_path}")
    print(df.describe().round(2).to_string())


if __name__ == "__main__":
    main()
