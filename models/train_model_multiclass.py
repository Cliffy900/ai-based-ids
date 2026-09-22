"""
models/train_model_multiclass.py

Stage 2 of the hybrid detection approach: given a flow already flagged
as an attack (by the binary classifier), predict which specific attack
type it is. Trained only on attack rows from the corrected dataset.

Design choices, stated explicitly:
- "X - Attempted" labels are merged into their base class "X" -- the
  attack TYPE is unchanged by whether it ultimately succeeded.
- Classes with fewer than 50 samples after merging are dropped, since
  there isn't enough data for a meaningful train/test evaluation. These
  attacks are still caught by the binary classifier as ATTACK; they
  simply don't get a specific type label from this model.
"""

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from preprocessing.feature_schema import FEATURE_COLUMNS

DATASET_PATH = "data/datasets/CICIDS2017_corrected/combined_cleaned_corrected.csv"
MODEL_OUTPUT_DIR = "saved_models"
MIN_CLASS_SIZE = 50




def load_and_prepare():
    print(f"Loading {DATASET_PATH} ...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)

    # keep only attack rows -- this model only runs on flows already
    # flagged as ATTACK by the binary classifier
    df = df[df["Label"] != "BENIGN"].copy()
    print(f"Attack rows only: {df.shape[0]}")

    # merge "X - Attempted" into base label "X"
    df["attack_type"] = df["Label"].str.replace(r"\s*-\s*Attempted$", "", regex=True)

    print("\nAttack type distribution (after merging Attempted variants):")
    counts = df["attack_type"].value_counts()
    print(counts)

    # drop classes below the minimum sample threshold
    keep_classes = counts[counts >= MIN_CLASS_SIZE].index.tolist()
    dropped_classes = counts[counts < MIN_CLASS_SIZE].index.tolist()
    print(f"\nDropping rare classes (< {MIN_CLASS_SIZE} samples): {dropped_classes}")

    df = df[df["attack_type"].isin(keep_classes)]
    print(f"\nFinal shape after filtering: {df.shape}")
    print(f"Final classes ({len(keep_classes)}): {sorted(keep_classes)}")

    return df


def train_and_evaluate(df):
    X = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).dropna()
    y = df.loc[X.index, "attack_type"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain size: {X_train.shape[0]}, Test size: {X_test.shape[0]}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\nTraining multi-class RandomForestClassifier ...")
    model = RandomForestClassifier(
        n_estimators=150, max_depth=25, class_weight="balanced", n_jobs=-1, random_state=42,
    )
    model.fit(X_train_scaled, y_train)

    print("\nEvaluating on test set ...")
    y_pred = model.predict(X_test_scaled)

    print(f"\nOverall accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("Confusion Matrix (rows=true, cols=predicted):")
    labels = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    cm_df = pd.DataFrame(cm, index=labels, columns=labels)
    print(cm_df)

    importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print("\nTop 10 most important features:")
    print(importances.head(10))

    return model, scaler, labels


def save_model(model, scaler, labels):
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_OUTPUT_DIR, "multiclass_attack_model.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_OUTPUT_DIR, "multiclass_attack_scaler.joblib"))
    joblib.dump(labels, os.path.join(MODEL_OUTPUT_DIR, "multiclass_attack_labels.joblib"))
    print("\nSaved multi-class model, scaler, and label list to saved_models/")


if __name__ == "__main__":
    df = load_and_prepare()
    model, scaler, labels = train_and_evaluate(df)
    save_model(model, scaler, labels)