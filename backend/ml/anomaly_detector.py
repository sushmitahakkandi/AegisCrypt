"""
Anomaly Detector — Isolation Forest for login anomaly detection.
Trains on synthetic normal login data on first run, saves model with joblib.
"""

import os
import numpy as np
from datetime import datetime
import joblib
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.joblib')


def _generate_synthetic_data(n_samples=500):
    """Generate synthetic 'normal' login data for initial training."""
    np.random.seed(42)
    data = np.column_stack([
        np.random.uniform(8, 22, n_samples),           # hour_of_day (normal hours)
        np.random.choice([0, 1, 2, 3, 4], n_samples),  # day_of_week (weekdays)
        np.random.randint(0, 2, n_samples),             # failed_attempts_10min
        np.random.uniform(0, 0.3, n_samples),           # ip_novelty_score
        np.random.uniform(0, 0.2, n_samples),           # device_novelty_score
    ])
    return data


def train_model():
    """Train Isolation Forest on synthetic data and save."""
    data = _generate_synthetic_data()
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
    )
    model.fit(data)
    joblib.dump(model, MODEL_PATH)
    print("[+] Anomaly detection model trained and saved (synthetic).")
    return model


def retrain_model(real_data):
    """Retrain Isolation Forest on actual historical data."""
    if not real_data or len(real_data) < 10:
        print("[-] Not enough real data to retrain model. Using current model.")
        return load_model()

    # Create dataset based on 'hour_of_day', 'day_of_week', 'failed_attempts', 'ip_novelty', 'device_novelty'
    features = []
    
    # We expect real_data to be a list of dicts with these exact keys, or tuples that we parse.
    # We will assume it's a list of dicts for safety, populated by the calling route.
    for row in real_data:
        features.append([
            row.get('hour_of_day', 12),
            row.get('day_of_week', 0),
            row.get('failed_attempts', 0),
            row.get('ip_novelty', 0.1),
            row.get('device_novelty', 0.1)
        ])
        
    data = np.array(features)
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
    )
    model.fit(data)
    joblib.dump(model, MODEL_PATH)
    print(f"[+] Anomaly detection model retrained on {len(data)} actual records.")
    return model


def load_model():
    """Load or train the anomaly detection model."""
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return train_model()


def predict_anomaly(hour_of_day, day_of_week, failed_attempts, ip_novelty, device_novelty):
    """Predict if a login attempt is anomalous.
    Returns (is_anomaly: bool, anomaly_score: float).
    """
    model = load_model()
    features = np.array([[hour_of_day, day_of_week, failed_attempts, ip_novelty, device_novelty]])
    prediction = model.predict(features)[0]   # 1 = normal, -1 = anomaly
    score = model.decision_function(features)[0]  # lower = more anomalous
    is_anomaly = prediction == -1
    # Normalize score to 0-1 range (0 = normal, 1 = highly anomalous)
    normalized_score = max(0, min(1, 0.5 - score))
    return is_anomaly, round(float(normalized_score), 4)
