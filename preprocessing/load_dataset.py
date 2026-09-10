"""
preprocessing/load_dataset.py

Loads all CICIDS2017 CSVs, strips whitespace from column headers,
selects only the feature subset matching Flow.extract_features(),
and combines them into one clean DataFrame for training.
"""

import os
import pandas as pd

DATASET_DIR = "data/datasets/CICIDS2017/MachineLearningCVE"

# exact feature names produced by Flow.extract_features(), plus Label
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "Fwd Header Length",
    "Bwd Header Length",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Label",
]


def load_all_csvs(dataset_dir=DATASET_DIR):
    """
    Loads every CSV in the dataset folder, strips whitespace from
    column names, filters down to FEATURE_COLUMNS, and concatenates
    them into one DataFrame.
    """
    all_dfs = []

    csv_files = [f for f in os.listdir(dataset_dir) if f.endswith(".csv")]
    print(f"Found {len(csv_files)} CSV files: {csv_files}")

    for filename in csv_files:
        filepath = os.path.join(dataset_dir, filename)
        print(f"Loading {filename} ...")

        df = pd.read_csv(filepath, low_memory=False)

        # strip whitespace from column headers (CICIDS2017's known quirk)
        df.columns = [col.strip() for col in df.columns]

        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing:
            print(f"  WARNING: {filename} is missing columns: {missing}")

        # keep only the columns we care about (that actually exist)
        available_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
        df = df[available_cols]

        df["source_file"] = filename  # helpful for debugging later
        all_dfs.append(df)

        print(f"  -> {df.shape[0]} rows loaded")

    combined = pd.concat(all_dfs, ignore_index=True)
    print(f"\nTOTAL combined shape: {combined.shape}")
    return combined


def clean_dataset(df):
    """
    Basic cleaning: handle infinities and NaNs that are common in
    CICIDS2017 due to division-by-zero during original feature
    generation (e.g. Flow Bytes/s on zero-duration flows).
    """
    import numpy as np

    before = df.shape[0]

    # replace inf/-inf with NaN, then drop rows with NaN in feature columns
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

    print("\nSample rows:")
    print(df.head())

    # save the cleaned, aligned dataset for use in train_model.py
    output_path = "data/datasets/CICIDS2017/combined_cleaned.csv"
    df.to_csv(output_path, index=False)
    print(f"\nSaved cleaned combined dataset to: {output_path}")