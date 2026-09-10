AI-Based Network Intrusion Detection System

A flow-based intrusion detection system that combines a machine learning classifier with a rule-based port-scan detector, built as a final year project. It captures live network traffic, aggregates it into flows, extracts CICIDS2017-style statistical features, and classifies each flow as benign or an attack.

Live demo (dashboard only, no live capture): https://ai-based-ids-4voz.onrender.com/

The dashboard runs the trained model live and shows real detection results, but doesn't perform packet capture itself — see Deployment scope below for why.

What it does
Captures live packets on a network interface and groups them into flows (5-tuple: source IP, destination IP, source port, destination port, protocol)
Extracts 30 statistical features per flow (packet length stats, flow duration, inter-arrival times, TCP flag counts, and more), matching the feature schema used by the CICIDS2017 dataset
Classifies each flow as BENIGN or ATTACK using a Random Forest model trained on ~2.8 million labeled flows
Runs a complementary host-level rule: flags a source IP if it contacts an unusually high number of distinct destination ports on the same target within a short time window, catching fast port scans that look unremarkable at the individual-flow level (see Limitations)
Logs and displays alerts through a web dashboard
Architecture
capture/            live packet capture (scapy), builds flow-ready packet dicts
preprocessing/       aggregates packets into flows, extracts features, loads/cleans CICIDS2017
models/              trains the Random Forest classifier
detection/           loads the trained model for live inference; rule-based scan detector
alerts/              alert logging (console + persistent JSONL log)
dashboard/           Flask web dashboard -- model stats, live detection demo, alert feed
saved_models/        trained model + scaler (committed, so the dashboard works out of the box)
data/datasets/       CICIDS2017 CSVs (not committed -- see Setup)

Data flow:

raw packets -> FlowTracker (flow aggregation) -> feature dict
                                                       |
                                    +------------------+------------------+
                                    v                                     v
                         Detector (ML classifier)          ScanDetector (host-level rule)
                                    |                                     |
                                    +------------------+------------------+
                                                       v
                                              AlertManager (log + display)
Model performance

Binary classifier (benign vs. attack), Random Forest, trained on CICIDS2017:

Metric	Score
Accuracy	99.71%
ROC AUC	0.9999
Attack precision / recall	0.99 / 1.00

Most influential features: Destination Port, Packet Length Std, Bwd Packet Length Mean, Fwd Packet Length Max, Bwd Packet Length Min.

Limitations

This project is a working prototype, not production security software. Documented honestly here rather than glossed over:

CICIDS2017 is a known-imperfect benchmark. Its headline accuracy numbers are widely reported as inflated relative to real-world traffic, partly because Destination Port alone is unusually predictive in this dataset -- retraining without it still reaches 98.68% accuracy, but the drop confirms the model leans on it. See Engelen et al., "Troubleshooting an Intrusion Detection Dataset" (2021), for a fuller critique.
Per-flow classification misses fast port scans. Live testing against a real nmap -sS scan showed that a stealth SYN scan produces flows containing a single packet each -- too little signal for the flow-level model to flag. This is the reason the project also includes a host-level rule-based scan detector as a complementary signal, rather than relying on the ML model alone.
Not tuned against slow/evasive scanning. The rule-based detector uses a fixed time window and port-count threshold; a slow scan (e.g. one port every 30+ seconds) would not trigger it.
Single-host, single-interface scope. Monitors traffic visible to one machine's network interface, not a full network chokepoint.
Not built for line-rate production traffic. The pipeline is single-threaded Python; a busy network (torrent traffic during testing produced hundreds of flows per second) will outpace it. Real IDS tools (Snort, Suricata, Zeek) are built and optimized for exactly this reason.
Deployment scope

Live packet capture needs raw socket access and a real network interface -- it can't run in a typical cloud container, and there'd be no meaningful network for it to capture on a hosting platform anyway. So what's deployed is the dashboard only: the trained model, real example flows from the dataset, and a live "run a detection" panel that calls the actual model. Packet capture and the full pipeline run locally -- see Setup below.

Setup
Requirements
Python 3.10+
Npcap (Windows) or equivalent packet capture driver, for live capture only
nmap, optional, for testing the scan detector
Install
bash
git clone https://github.com/Cliffy900/ai-based-ids.git
cd ai-based-ids
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
pip install scapy             # only needed for live capture, not the dashboard
Run the dashboard (no live capture needed)
bash
python -m dashboard.app

Open http://127.0.0.1:5000.

Run live capture (requires admin/root and Npcap)
bash
python -m capture.packet_capture
Retrain the model

Download CICIDS2017 (MachineLearningCSV) into data/datasets/CICIDS2017/MachineLearningCVE/, then:

bash
python -m preprocessing.load_dataset
python -m models.train_model
Tech stack

Python, scikit-learn, pandas, scapy, Flask, gunicorn. Dataset: CICIDS2017.

Future work
Multi-class attack-type classification (currently binary only)
Combine the ML and rule-based signals into a single ensemble decision rather than two parallel outputs
Evaluate against a more current dataset (e.g. CICIoT2023) to test generalization beyond CICIDS2017's 2017-era traffic patterns
Compare against a second model architecture (e.g. XGBoost) for the evaluation chapter
License

MIT -- see LICENSE.