"""
models/train_model.py

Trains a binary classifier (BENIGN vs ATTACK) on the cleaned,
combined CICIDS2017 dataset produced by preprocessing/load_dataset.py.
"""

import os

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
)

from preprocessing.feature_schema import FEATURE_COLUMNS


DATASET_PATH = "data/datasets/CICIDS2017/combined_cleaned.csv"
MODEL_OUTPUT_DIR = "saved_models"


def load_data():
    print(f"Loading dataset from {DATASET_PATH} ...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f"Loaded shape: {df.shape}")
    return df


def prepare_binary_labels(df):
    """
    Collapses the multi-class Label column into binary:
    0 = BENIGN, 1 = ATTACK (anything not BENIGN)
    """
    df["binary_label"] = df["Label"].apply(
        lambda x: 0 if x.strip() == "BENIGN" else 1
    )

    print("\nBinary label distribution:")
    print(df["binary_label"].value_counts())
    print("  0 = BENIGN, 1 = ATTACK")

    return df


def train_and_evaluate(df):
    X = df[FEATURE_COLUMNS]
    y = df["binary_label"]

    # Stratify keeps the same class ratio in train and test splits,
    # important given the imbalance (only ~20% attack traffic).
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain size: {X_train.shape[0]}, Test size: {X_test.shape[0]}")

    # Scale features. RandomForest doesn't strictly need this, but
    # keeping the scaler lets you swap in other models later (SVM, NN)
    # without re-deriving the pipeline.
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\nTraining RandomForestClassifier ...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_scaled, y_train)

    print("\nEvaluating on test set ...")
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.4f}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print("  [ [TN  FP]")
    print("    [FN  TP] ]")

    # Feature importance is useful for the report/dissertation to
    # discuss which flow characteristics matter most for detection.
    importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
    importances = importances.sort_values(ascending=False)

    print("\nTop 10 most important features:")
    print(importances.head(10))

    return model, scaler


def save_model(model, scaler):
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)

    model_path = os.path.join(MODEL_OUTPUT_DIR, "binary_ids_model.joblib")
    scaler_path = os.path.join(MODEL_OUTPUT_DIR, "binary_ids_scaler.joblib")

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    print(f"\nSaved model to: {model_path}")
    print(f"Saved scaler to: {scaler_path}")


if __name__ == "__main__":
    df = load_data()
    df = prepare_binary_labels(df)
    model, scaler = train_and_evaluate(df)
    save_model(model, scaler)