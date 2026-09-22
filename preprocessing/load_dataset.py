"""
preprocessing/load_dataset.py

Loads all CICIDS2017 CSVs, strips whitespace from column headers,
selects the feature subset matching Flow.extract_features()
plus the target Label column, and combines them into one clean
DataFrame for training.
"""

import os

import pandas as pd

from preprocessing.feature_schema import FEATURE_COLUMNS


DATASET_DIR = "data/datasets/CICIDS2017/MachineLearningCVE"

# Exact feature names produced by Flow.extract_features(), plus Label.
DATASET_COLUMNS = FEATURE_COLUMNS + ["Label"]


def load_all_csvs(dataset_dir=DATASET_DIR):
    """
    Loads every CSV in the dataset folder, strips whitespace from
    column names, validates the required feature and label columns,
    and concatenates them into one DataFrame.
    """
    all_dfs = []

    csv_files = [f for f in os.listdir(dataset_dir) if f.endswith(".csv")]
    print(f"Found {len(csv_files)} CSV files: {csv_files}")

    for filename in csv_files:
        filepath = os.path.join(dataset_dir, filename)
        print(f"Loading {filename} ...")

        df = pd.read_csv(filepath, low_memory=False)

        # Strip whitespace from column headers.
        # CICIDS2017 CSVs commonly contain extra whitespace.
        df.columns = [col.strip() for col in df.columns]

        # Every dataset file must contain the complete schema.
        missing = [c for c in DATASET_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(
                f"{filename} is missing required columns: {missing}"
            )

        # Keep exactly the canonical features plus the target label.
        df = df[DATASET_COLUMNS]

        # Helpful for debugging and tracing rows back to their source file.
        df["source_file"] = filename
        all_dfs.append(df)

        print(f"  -> {df.shape[0]} rows loaded")

    if not all_dfs:
        raise ValueError(
            f"No CSV files found in dataset directory: {dataset_dir}"
        )

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

    # Replace inf/-inf with NaN, then drop rows containing NaN.
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    after = df.shape[0]

    print(
        f"Cleaning: dropped {before - after} rows with inf/NaN values"
    )

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

    # Save the cleaned, aligned dataset for use in train_model.py.
    output_path = "data/datasets/CICIDS2017/combined_cleaned.csv"
    df.to_csv(output_path, index=False)

    print(f"\nSaved cleaned combined dataset to: {output_path}")