"""
models/train_model_xgboost.py

Trains an XGBoost binary classifier on the same corrected dataset used
for the Random Forest model, for direct comparison in the evaluation
chapter -- same data, same train/test split, same features, different
algorithm.
"""

import os
import joblib
import pandas as pd
import numpy as np
import time

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
)
from xgboost import XGBClassifier

DATASET_PATH = "data/datasets/CICIDS2017_corrected/combined_cleaned_corrected.csv"
MODEL_OUTPUT_DIR = "saved_models"

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


def load_data():
    print(f"Loading dataset from {DATASET_PATH} ...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f"Loaded shape: {df.shape}")
    return df


def prepare_binary_labels(df):
    df["binary_label"] = df["Label"].apply(lambda x: 0 if x.strip() == "BENIGN" else 1)
    print("\nBinary label distribution:")
    print(df["binary_label"].value_counts())
    return df


def train_and_evaluate(df):
    X = df[FEATURE_COLUMNS]
    y = df["binary_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain size: {X_train.shape[0]}, Test size: {X_test.shape[0]}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # scale_pos_weight compensates for class imbalance, XGBoost's
    # equivalent of scikit-learn's class_weight="balanced"
    neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
    scale_pos_weight = neg / pos
    print(f"scale_pos_weight (imbalance correction): {scale_pos_weight:.3f}")

    print("\nTraining XGBClassifier ...")
    start = time.time()
    model = XGBClassifier(
        n_estimators=150,
        max_depth=8,
        learning_rate=0.15,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_scaled, y_train)
    train_time = time.time() - start
    print(f"Training completed in {train_time:.1f} seconds")

    print("\nEvaluating on test set ...")
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print("\nTop 10 most important features:")
    print(importances.head(10))

    return model, scaler, train_time


def save_model(model, scaler):
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_OUTPUT_DIR, "binary_ids_model_xgboost.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_OUTPUT_DIR, "binary_ids_scaler_xgboost.joblib"))
    print("\nSaved XGBoost model and scaler to saved_models/")


if __name__ == "__main__":
    df = load_data()
    df = prepare_binary_labels(df)
    model, scaler, train_time = train_and_evaluate(df)
    save_model(model, scaler)
    print(f"\n--- Training time: {train_time:.1f}s (compare against Random Forest's wall-clock time) ---")