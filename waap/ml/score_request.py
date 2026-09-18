"""Fase 3.4 (PDF p.12): inferencia sobre una peticion entrante."""
import joblib
import pandas as pd

from extract_features import extract

_bundle = joblib.load("waap/ml/model.pkl")
model, scaler = _bundle["model"], _bundle["scaler"]

ANOMALY_THRESHOLD = -0.05


def score(features: dict) -> float:
    X = pd.DataFrame([features])
    X_scaled = scaler.transform(X)
    # decision_function: valores negativos => mas anomalo
    return float(model.decision_function(X_scaled)[0])


def score_request(url: str, body: str = "", req_per_minute: int = 0) -> float:
    return score(extract({"url": url, "body": body, "req_per_minute": req_per_minute}))


def is_anomalous(features: dict) -> bool:
    return score(features) < ANOMALY_THRESHOLD
