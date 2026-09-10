"""
dashboard/app.py

Web dashboard for the AI-based IDS project. Deliberately has no
dependency on live packet capture (scapy) so it can be deployed
anywhere Python + Flask run -- it reads the trained model and the
saved alert log, and offers a "try a detection" panel that runs the
real model on preset or custom flow feature values.

Run locally:
    python -m dashboard.app
Then open http://127.0.0.1:5000
"""

import os
import sys
import json

from flask import Flask, render_template, request

# --- path setup so this works whether run from project root or elsewhere ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

MODEL_PATH = os.path.join(PROJECT_ROOT, "saved_models", "binary_ids_model.joblib")
SCALER_PATH = os.path.join(PROJECT_ROOT, "saved_models", "binary_ids_scaler.joblib")
ALERTS_LOG_PATH = os.path.join(PROJECT_ROOT, "alerts", "logs", "alerts.jsonl")

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(DASHBOARD_DIR, "templates"),
    static_folder=os.path.join(DASHBOARD_DIR, "static"),
)

# --- load the model once at startup (falls back gracefully if missing,
# so the dashboard still renders even without saved_models/ present --
# useful for a first deploy before the model file is uploaded) ---
detector = None
model_load_error = None
try:
    from detection.detector import Detector
    detector = Detector(model_path=MODEL_PATH, scaler_path=SCALER_PATH)
except Exception as e:
    model_load_error = str(e)


# --- static project facts, shown in the "model performance" panel ---
MODEL_STATS = {
    "accuracy": "99.71%",
    "roc_auc": "0.9999",
    "training_rows": "2,827,876",
    "attack_rows": "556,556",
    "benign_rows": "2,271,320",
    "top_features": [
        ("Destination Port", 0.113),
        ("Packet Length Std", 0.073),
        ("Bwd Packet Length Mean", 0.069),
        ("Fwd Packet Length Max", 0.064),
        ("Bwd Packet Length Min", 0.063),
    ],
}

# --- preset flows for the "try a detection" panel, matching the exact
# feature schema the model was trained on ---
PRESETS = {
    "benign_example": {
        "label": "Benign flow (real example)",
        "description": "An actual BENIGN-labeled flow from the CICIDS2017 test set.",
        "features": {
            "Destination Port": 54865, "Flow Duration": 3,
            "Total Fwd Packets": 2, "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 12, "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": 6, "Fwd Packet Length Min": 6,
            "Fwd Packet Length Mean": 6.0, "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0, "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0.0, "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": 4000000.0, "Flow Packets/s": 666666.6667,
            "Flow IAT Mean": 3.0, "Flow IAT Std": 0.0,
            "Flow IAT Max": 3, "Flow IAT Min": 3,
            "Fwd PSH Flags": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
            "ACK Flag Count": 1, "FIN Flag Count": 0,
            "Fwd Header Length": 40, "Bwd Header Length": 0,
            "Min Packet Length": 6, "Max Packet Length": 6,
            "Packet Length Mean": 6.0, "Packet Length Std": 0.0,
        },
    },
    "dos_hulk_example": {
        "label": "DoS Hulk attack (real example)",
        "description": "An actual DoS Hulk-labeled flow from the CICIDS2017 test set.",
        "features": {
            "Destination Port": 80, "Flow Duration": 1878,
            "Total Fwd Packets": 3, "Total Backward Packets": 6,
            "Total Length of Fwd Packets": 382, "Total Length of Bwd Packets": 11595,
            "Fwd Packet Length Max": 382, "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 127.3333333, "Fwd Packet Length Std": 220.5478028,
            "Bwd Packet Length Max": 4355, "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 1932.5, "Bwd Packet Length Std": 2182.468304,
            "Flow Bytes/s": 6377529.286, "Flow Packets/s": 4792.332268,
            "Flow IAT Mean": 234.75, "Flow IAT Std": 229.1298758,
            "Flow IAT Max": 577, "Flow IAT Min": 15,
            "Fwd PSH Flags": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
            "ACK Flag Count": 0, "FIN Flag Count": 0,
            "Fwd Header Length": 104, "Bwd Header Length": 200,
            "Min Packet Length": 0, "Max Packet Length": 4355,
            "Packet Length Mean": 1197.7, "Packet Length Std": 1886.332364,
        },
    },
    "portscan_example": {
        "label": "Port scan (real example)",
        "description": "An actual PortScan-labeled flow from CICIDS2017 -- note it has multiple packets, unlike the single-SYN probes seen in live scan testing (see write-up).",
        "features": {
            "Destination Port": 80, "Flow Duration": 5021059,
            "Total Fwd Packets": 6, "Total Backward Packets": 5,
            "Total Length of Fwd Packets": 703, "Total Length of Bwd Packets": 1414,
            "Fwd Packet Length Max": 356, "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 117.1666667, "Fwd Packet Length Std": 181.5361305,
            "Bwd Packet Length Max": 1050, "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 282.8, "Bwd Packet Length Std": 456.923626,
            "Flow Bytes/s": 421.6242032, "Flow Packets/s": 2.190772903,
            "Flow IAT Mean": 502105.9, "Flow IAT Std": 1568379.157,
            "Flow IAT Max": 4965658, "Flow IAT Min": 19,
            "Fwd PSH Flags": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
            "ACK Flag Count": 0, "FIN Flag Count": 0,
            "Fwd Header Length": 200, "Bwd Header Length": 168,
            "Min Packet Length": 0, "Max Packet Length": 1050,
            "Packet Length Mean": 176.4166667, "Packet Length Std": 317.4711034,
        },
    },
}

from datetime import datetime

def load_recent_alerts(limit=25):
    """Reads the persisted alert log directly off disk, newest first."""
    if not os.path.exists(ALERTS_LOG_PATH):
        return []
    alerts = []
    with open(ALERTS_LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            # normalize timestamp: scan alerts store a raw float (time.time()),
            # ML alerts store an ISO string -- make both a consistent string
            ts = alert.get("timestamp")
            if isinstance(ts, (int, float)):
                alert["timestamp"] = datetime.fromtimestamp(ts).isoformat()

            alerts.append(alert)
    return list(reversed(alerts))[:limit]

@app.route("/", methods=["GET"])
def index():
    result = None
    selected_preset = request.args.get("preset")
    if selected_preset and selected_preset in PRESETS and detector:
        result = detector.predict(PRESETS[selected_preset]["features"])
        result["preset_label"] = PRESETS[selected_preset]["label"]

    return render_template(
        "index.html",
        model_stats=MODEL_STATS,
        model_ready=detector is not None,
        model_error=model_load_error,
        presets=PRESETS,
        selected_preset=selected_preset,
        result=result,
        alerts=load_recent_alerts(),
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
