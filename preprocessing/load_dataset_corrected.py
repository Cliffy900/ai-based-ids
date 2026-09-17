"""
preprocessing/load_dataset_corrected.py

Loads the corrected CICIDS2017 dataset (Engelen et al., 2021), renames
columns to match this project's existing canonical feature schema, and
produces a cleaned combined CSV -- so train_model.py and detector.py
require no changes to work with either dataset version.
"""

import os
import numpy as np
import pandas as pd

DATASET_DIR = "data/datasets/CICIDS2017_corrected"

# maps the corrected dataset's column names onto this project's
# existing canonical feature names
COLUMN_RENAME_MAP = {
    "Dst Port": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
}

FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd PSH Flags", "SYN Flag Count", "RST Flag Count", "ACK Flag Count", "FIN Flag Count",
    "Fwd Header Length", "Bwd Header Length", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std",
    "Label",
]


def load_all_csvs(dataset_dir=DATASET_DIR):
    all_dfs = []
    csv_files = [f for f in os.listdir(dataset_dir) if f.endswith(".csv")]
    print(f"Found {len(csv_files)} CSV files: {csv_files}")

    for filename in csv_files:
        filepath = os.path.join(dataset_dir, filename)
        print(f"Loading {filename} ...")

        df = pd.read_csv(filepath, low_memory=False)
        df.columns = [col.strip() for col in df.columns]
        df = df.rename(columns=COLUMN_RENAME_MAP)

        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing:
            print(f"  WARNING: {filename} is missing columns after rename: {missing}")

        available_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
        df = df[available_cols]
        df["source_file"] = filename
        all_dfs.append(df)

        print(f"  -> {df.shape[0]} rows loaded")

    combined = pd.concat(all_dfs, ignore_index=True)
    print(f"\nTOTAL combined shape: {combined.shape}")
    return combined


def clean_dataset(df):
    before = df.shape[0]
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    after = df.shape[0]
    print(f"Cleaning: dropped {before - after} rows with inf/NaN values")
    return df


if __name__ == "__main__":
    df = load_all_csvs()

    print("\nLabel distribution BEFORE cleaning:")
    print(df["Label"].value_counts())

    df = clean_dataset(df)

    print("\nLabel distribution AFTER cleaning:")
    print(df["Label"].value_counts())

    output_path = "data/datasets/CICIDS2017_corrected/combined_cleaned_corrected.csv"
    df.to_csv(output_path, index=False)
    print(f"\nSaved cleaned combined dataset to: {output_path}")