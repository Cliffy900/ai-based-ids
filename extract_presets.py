"""
extract_presets.py
Pulls one real example row per label from the cleaned dataset,
formatted as Python dicts ready to paste into dashboard/app.py's PRESETS.
"""
import pandas as pd

df = pd.read_csv("data/datasets/CICIDS2017/combined_cleaned.csv", low_memory=False)

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

for label in ["BENIGN", "DoS Hulk", "PortScan"]:
    matches = df[df["Label"] == label]
    if matches.empty:
        print(f"\n# --- {label}: NO ROWS FOUND ---")
        continue
    row = matches.iloc[0]
    print(f"\n# --- {label} ---")
    print("{")
    for col in FEATURE_COLUMNS:
        print(f'    "{col}": {row[col]},')
    print("}")