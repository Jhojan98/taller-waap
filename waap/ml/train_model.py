"""Fase 3.3 (PDF p.11-12): entrenamiento del modelo de deteccion de anomalias."""
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["url_length", "body_length", "entropy", "n_params",
            "has_suspicious_chars", "req_per_minute"]


def main(csv_path="logs/features_normal_traffic.csv", out_path="waap/ml/model.pkl"):
    df = pd.read_csv(csv_path)  # solo trafico normal
    X = df[FEATURES].astype(float)
    scaler = StandardScaler().fit(X)
    X_scaled = scaler.transform(X)
    model = IsolationForest(
        n_estimators=200, contamination=0.02, random_state=42
    ).fit(X_scaled)
    joblib.dump({"model": model, "scaler": scaler}, out_path)
    print(f"Modelo entrenado y guardado en {out_path} ({len(df)} muestras)")


if __name__ == "__main__":
    main()
