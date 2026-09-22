# AI-Based Network Intrusion Detection System

A flow-based intrusion detection system that combines a machine learning classifier with a rule-based port-scan detector, built as a final year project.

It captures live network traffic, aggregates it into flows, extracts CICIDS2017-style statistical features, and classifies each flow as benign or an attack.

**Live demo (dashboard only, no live capture):**
https://ai-based-ids-4voz.onrender.com/

The dashboard runs the trained model live and shows real detection results, but does not perform packet capture itself — see [Deployment scope](#deployment-scope) for why.

---

## What it does

- Captures live packets on a network interface and groups them into flows using a 5-tuple:
  - Source IP
  - Destination IP
  - Source port
  - Destination port
  - Protocol
- Extracts **31 statistical features per flow**, including packet-length statistics, flow duration, inter-arrival times, TCP flag counts, and other traffic characteristics.
- Uses a centralized feature schema shared by the preprocessing, training, and detection pipelines.
- Classifies each flow as **BENIGN** or **ATTACK** using a Random Forest model trained on approximately 2.8 million labeled flows.
- Runs a complementary host-level rule that flags a source IP if it contacts an unusually high number of distinct destination ports on the same target within a short time window.
- Combines the ML and rule-based signals into a single ensemble detection decision.
- Uses a multiclass classifier to estimate the attack type when the ML model identifies an attack.
- Logs and displays alerts through a web dashboard.

---

## Architecture

```text
capture/
    Live packet capture (Scapy)
    Builds flow-ready packet dictionaries

        ↓

preprocessing/
    Flow aggregation
    Feature extraction
    Dataset loading and cleaning
    Canonical feature schema

        ↓

detection/
    ┌──────────────────────┐
    │ Binary ML Detector   │
    │ Random Forest        │
    └──────────────────────┘
              │
              │
    ┌──────────────────────┐
    │ Scan Detector        │
    │ Host-level rule      │
    └──────────────────────┘
              │
              ↓
       Ensemble Detector
              │
              ↓
    ┌──────────────────────┐
    │ Multiclass Detector  │
    │ Attack-type model    │
    └──────────────────────┘
              │
              ↓
        Alert Manager
        (log + display)

              ↓

        Web Dashboard
```

### Project structure

```text
capture/
    Live packet capture and flow generation

preprocessing/
    Feature extraction
    Dataset loading and cleaning
    Shared feature schema

models/
    Model training scripts

detection/
    Binary ML detection
    Multiclass attack classification
    Rule-based scan detection
    Ensemble decision logic

alerts/
    Alert logging

dashboard/
    Flask web dashboard

saved_models/
    Trained models and scalers

data/datasets/
    CICIDS2017 datasets
    (not committed — see Setup)
```

The trained model and scaler are committed so that the dashboard can run without retraining.

---

## Data flow

```text
Raw packets
     │
     ▼
FlowTracker
     │
     ▼
31-feature flow vector
     │
     ├───────────────┐
     ▼               ▼
ML Detector     Scan Detector
     │               │
     └───────┬───────┘
             ▼
      Ensemble Detector
             │
             ▼
    Attack / Benign decision
             │
             ▼
       Alert Manager
             │
             ▼
        Dashboard
```

---

## Model performance

### Binary classifier

**Task:** Benign vs. Attack
**Algorithm:** Random Forest
**Dataset:** CICIDS2017

| Metric | Score |
|---|---:|
| Accuracy | 99.71% |
| ROC AUC | 0.9999 |
| Attack precision | 0.99 |
| Attack recall | 1.00 |

Most influential features in the trained model include:

- Destination Port
- Packet Length Std
- Bwd Packet Length Mean
- Fwd Packet Length Max
- Bwd Packet Length Min

These results are reported for the project's CICIDS2017 evaluation and should not be interpreted as equivalent performance on arbitrary real-world network traffic.

---

## Limitations

This project is a working prototype, not production security software. The limitations are documented rather than hidden.

### CICIDS2017 dataset limitations

CICIDS2017 is a known-imperfect benchmark. Its headline accuracy numbers can be optimistic relative to real-world traffic, partly because features such as Destination Port are unusually predictive in this dataset.

Retraining without Destination Port still reaches 98.68% accuracy, but the difference indicates that the original model makes substantial use of this feature.

See Engelen et al., *Troubleshooting an Intrusion Detection Dataset* (2021), for a detailed discussion of CICIDS2017 dataset issues.

### Per-flow classification

Per-flow classification can miss fast port scans.

Live testing against an `nmap -sS` scan showed that a stealth SYN scan can produce flows containing only a single packet each, providing too little information for the flow-level ML model to reliably identify the scan.

This is why the project also includes a host-level rule-based scan detector rather than relying on the ML model alone.

### Slow and evasive scans

The rule-based detector currently uses a fixed time window and port-count threshold.

A slow scan, such as contacting one port every 30 or more seconds, may not trigger the detector.

### Single-host, single-interface scope

The system monitors traffic visible to one machine's network interface. It is not designed to operate as a network-wide monitoring point or full network chokepoint.

### Performance

The pipeline is implemented in Python and is not designed for line-rate production traffic.

During testing, high-volume traffic such as torrent traffic produced hundreds of flows per second and can exceed the processing capacity of the current single-threaded pipeline.

Production IDS platforms such as Snort, Suricata, and Zeek are specifically engineered for higher-throughput monitoring environments.

---

## Deployment scope

Live packet capture requires raw socket access and a real network interface. A typical cloud container cannot provide the same packet-capture environment available on a local machine.

Therefore, the deployed Render application provides the **dashboard and model inference functionality**, rather than local packet capture.

The deployed dashboard includes:

- The trained model
- Real example flows from the dataset
- A live detection panel that calls the actual trained model
- Detection results and model information

The complete packet-capture pipeline runs locally.

---

## Setup

### Requirements

- Python 3.10+
- Npcap (Windows) or an equivalent packet-capture driver
- `nmap` (optional, for testing the scan detector)
- Administrator/root privileges for live packet capture

### Clone the repository

```bash
git clone https://github.com/Cliffy900/ai-based-ids.git
cd ai-based-ids
```

### Create a virtual environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Install dependencies

```bash
python -m pip install -r requirements.txt
```

Scapy is included in `requirements.txt`, so no separate Scapy installation is required.

---

## Run the dashboard

Live packet capture is not required for the dashboard.

```bash
python -m dashboard.app
```

Open:

```text
http://127.0.0.1:5000
```

---

## Run live capture

Live capture requires the appropriate packet-capture driver and administrator/root privileges.

```bash
python -m capture.packet_capture
```

---

## Retrain the model

Download the CICIDS2017 MachineLearningCSV dataset and place the CSV files in:

```text
data/datasets/CICIDS2017/MachineLearningCVE/
```

Then run:

```bash
python -m preprocessing.load_dataset
python -m models.train_model
```

The preprocessing stage creates the cleaned combined dataset used by the training pipeline.

---

## Testing

The project includes tests for the rule-based scan detector and the ensemble detection logic.

Run the ensemble test with:

```bash
python -m detection.test_ensemble
```

The ensemble test verifies:

1. An ML attack signal produces an ATTACK decision.
2. A benign flow without scan activity remains BENIGN.
3. A rule-based port-scan signal can override an ML BENIGN result.

---

## Tech stack

- **Python**
- **Scikit-learn**
- **Pandas**
- **NumPy**
- **Scapy**
- **Flask**
- **Gunicorn**
- **CICIDS2017**

### Machine learning

- Random Forest — binary classification
- Random Forest — multiclass attack classification
- StandardScaler — feature scaling
- XGBoost — additional model for comparison/evaluation

---

## Future work

- Evaluate the multiclass attack-type classifier more extensively and improve attack-type coverage in live detection.
- Evaluate against a more current dataset, such as CICIoT2023, to test generalization beyond CICIDS2017's 2017-era traffic patterns.
- Compare the Random Forest model against a second model architecture, such as XGBoost, for the evaluation chapter.
- Improve detection of slow and evasive scans by replacing the fixed port-count/time-window heuristic with more adaptive behavior analysis.
- Evaluate the system against traffic distributions that differ from the CICIDS2017 training environment.

---

## License

MIT — see [LICENSE](LICENSE).
