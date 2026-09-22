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

from preprocessing.feature_schema import FEATURE_COLUMNS


MODEL_DIR = "saved_models"
MODEL_PATH = os.path.join(MODEL_DIR, "multiclass_attack_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "multiclass_attack_scaler.joblib")
LABELS_PATH = os.path.join(MODEL_DIR, "multiclass_attack_labels.joblib")


class MulticlassDetector:
    def __init__(
        self,
        model_path=MODEL_PATH,
        scaler_path=SCALER_PATH,
        labels_path=LABELS_PATH,
    ):
        print(f"Loading multi-class model from {model_path} ...")
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.labels = joblib.load(labels_path)
        print("Multi-class detector ready.")

    def predict_type(self, flow_features: dict) -> dict:
        """
        Predict the attack type for a flow already classified as an attack.

        Missing model features are rejected instead of silently replaced
        with zero, preventing schema mismatches from producing
        unreliable attack-type predictions.
        """
        missing = [col for col in FEATURE_COLUMNS if col not in flow_features]

        if missing:
            raise ValueError(
                f"Flow is missing required model features: {missing}"
            )

        row = {col: flow_features[col] for col in FEATURE_COLUMNS}
        df_row = pd.DataFrame([row], columns=FEATURE_COLUMNS)
        df_row = df_row.replace([np.inf, -np.inf], 0).fillna(0)

        X_scaled = self.scaler.transform(df_row)

        pred = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0]
        confidence = float(max(proba))

        return {
            "attack_type": pred,
            "type_confidence": confidence,
        }