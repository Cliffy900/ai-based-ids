"""
detection/multiclass_detector.py

Loads the multi-class attack-type model. Only meaningful to call on a
flow already judged to be an attack -- this model was trained solely
on attack rows, so it has no concept of "benign" and will always
return some attack label, even for benign input.
"""

import os
import joblib
import numpy as np
import pandas as pd

MODEL_DIR = "saved_models"
MODEL_PATH = os.path.join(MODEL_DIR, "multiclass_attack_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "multiclass_attack_scaler.joblib")
LABELS_PATH = os.path.join(MODEL_DIR, "multiclass_attack_labels.joblib")

FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd PSH Flags", "SYN Flag Count", "RST Flag Count", "ACK Flag Count", "FIN Flag Count",
    "Fwd Header Length", "Bwd Header Length", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std",
]


class MulticlassDetector:
    def __init__(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH, labels_path=LABELS_PATH):
        print(f"Loading multi-class model from {model_path} ...")
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.labels = joblib.load(labels_path)
        print("Multi-class detector ready.")

    def predict_type(self, flow_features: dict) -> dict:
        row = {col: flow_features.get(col, 0) for col in FEATURE_COLUMNS}
        df_row = pd.DataFrame([row], columns=FEATURE_COLUMNS)
        df_row = df_row.replace([np.inf, -np.inf], 0).fillna(0)

        X_scaled = self.scaler.transform(df_row)
        pred = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0]
        confidence = float(max(proba))

        return {"attack_type": pred, "type_confidence": confidence}