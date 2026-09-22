"""
Canonical feature schema used by the IDS training and detection pipelines.

Keeping the feature order in one place prevents the training and live
inference pipelines from silently using different feature layouts.
"""

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
]