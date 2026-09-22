"""
detection/detector.py

Loads the trained binary IDS model and applies it to live flow
features produced by preprocessing/feature_extraction.py's FlowTracker.
"""

import os

import joblib
import numpy as np
import pandas as pd

from preprocessing.feature_schema import FEATURE_COLUMNS


MODEL_DIR = "saved_models"
MODEL_PATH = os.path.join(MODEL_DIR, "binary_ids_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "binary_ids_scaler.joblib")

METADATA_KEYS = ["_src_ip", "_dst_ip", "_src_port", "_protocol"]


class Detector:
    def __init__(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        print(f"Loading model from {model_path} ...")
        self.model = joblib.load(model_path)

        print(f"Loading scaler from {scaler_path} ...")
        self.scaler = joblib.load(scaler_path)

        print("Detector ready.")

    def _flow_to_feature_vector(self, flow_features: dict):
        """
        Convert a flow feature dictionary into the exact feature order
        expected by the trained model.

        Missing model features are rejected instead of silently replaced
        with zero, which could hide schema mismatches and produce
        unreliable predictions.
        """
        missing = [col for col in FEATURE_COLUMNS if col not in flow_features]

        if missing:
            raise ValueError(
                f"Flow is missing required model features: {missing}"
            )

        row = {col: flow_features[col] for col in FEATURE_COLUMNS}
        return pd.DataFrame([row], columns=FEATURE_COLUMNS)

    def predict(self, flow_features: dict):
        X = self._flow_to_feature_vector(flow_features)
        X = X.replace([np.inf, -np.inf], 0).fillna(0)

        X_scaled = self.scaler.transform(X)

        pred = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0]

        attack_probability = proba[1]
        confidence = proba[pred]

        result = {
            "prediction": "ATTACK" if pred == 1 else "BENIGN",
            "confidence": float(confidence),
            "attack_probability": float(attack_probability),
            "src_ip": flow_features.get("_src_ip"),
            "dst_ip": flow_features.get("_dst_ip"),
            "src_port": flow_features.get("_src_port"),
            "dst_port": flow_features.get("Destination Port"),
            "protocol": flow_features.get("_protocol"),
        }

        return result


if __name__ == "__main__":
    detector = Detector()

    sample_flow = {
        "Destination Port": 80,
        "Flow Duration": 0.05,
        "Total Fwd Packets": 5,
        "Total Backward Packets": 3,
        "Total Length of Fwd Packets": 500,
        "Total Length of Bwd Packets": 1200,
        "Fwd Packet Length Max": 150,
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": 100,
        "Fwd Packet Length Std": 30,
        "Bwd Packet Length Max": 500,
        "Bwd Packet Length Min": 300,
        "Bwd Packet Length Mean": 400,
        "Bwd Packet Length Std": 50,
        "Flow Bytes/s": 34000,
        "Flow Packets/s": 160,
        "Flow IAT Mean": 0.01,
        "Flow IAT Std": 0.005,
        "Flow IAT Max": 0.02,
        "Flow IAT Min": 0.001,
        "Fwd PSH Flags": 1,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
        "ACK Flag Count": 4,
        "FIN Flag Count": 0,
        "Fwd Header Length": 100,
        "Bwd Header Length": 60,
        "Min Packet Length": 60,
        "Max Packet Length": 500,
        "Packet Length Mean": 200,
        "Packet Length Std": 100,
        "_src_ip": "192.168.1.5",
        "_dst_ip": "8.8.8.8",
        "_src_port": 5000,
        "_protocol": "TCP",
    }

    result = detector.predict(sample_flow)
    print("\nPrediction result:")
    print(result)