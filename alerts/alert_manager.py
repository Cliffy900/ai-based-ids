"""
alerts/alert_manager.py

Handles what happens when the detector flags a flow as an attack:
logging to file, console warnings, and in-memory storage for the
dashboard to query.
"""

import os
import json
from datetime import datetime
from collections import deque

ALERTS_LOG_DIR = "alerts/logs"
ALERTS_LOG_FILE = os.path.join(ALERTS_LOG_DIR, "alerts.jsonl")

# how many recent alerts to keep in memory for quick dashboard access
MAX_RECENT_ALERTS = 500

# only alert if the model's attack probability crosses this threshold
# (lets you tune sensitivity without retraining)
ALERT_THRESHOLD = 0.5


class AlertManager:
    def __init__(self, log_file=ALERTS_LOG_FILE, alert_threshold=ALERT_THRESHOLD):
        self.log_file = log_file
        self.alert_threshold = alert_threshold
        self.recent_alerts = deque(maxlen=MAX_RECENT_ALERTS)

        os.makedirs(ALERTS_LOG_DIR, exist_ok=True)

    def process_detection(self, detection_result: dict):
        """
        detection_result: dict from Detector.predict(), e.g.
        {
            "prediction": "ATTACK",
            "confidence": 0.93,
            "attack_probability": 0.93,
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.5",
            "src_port": 5000,
            "dst_port": 80,
            "protocol": "TCP"
        }

        Returns True if an alert was raised, False otherwise.
        """
        if detection_result["prediction"] != "ATTACK":
            return False

        if detection_result["attack_probability"] < self.alert_threshold:
            return False

        alert = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": detection_result["src_ip"],
            "dst_ip": detection_result["dst_ip"],
            "src_port": detection_result["src_port"],
            "dst_port": detection_result["dst_port"],
            "protocol": detection_result["protocol"],
            "attack_probability": detection_result["attack_probability"],
            "confidence": detection_result["confidence"],
        }

        self._raise_alert(alert)
        return True

    def _raise_alert(self, alert: dict):
        # console warning, visually distinct from normal traffic logs
        print(
            f"\n🚨 ALERT [{alert['timestamp']}] "
            f"{alert['src_ip']}:{alert['src_port']} -> "
            f"{alert['dst_ip']}:{alert['dst_port']} "
            f"[{alert['protocol']}] "
            f"(attack probability: {alert['attack_probability']:.2%})\n"
        )

        # store in memory for quick dashboard access
        self.recent_alerts.append(alert)

        # append to persistent log file (JSON Lines format -- one
        # JSON object per line, easy to append to and easy to parse)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def get_recent_alerts(self, limit=50):
        """Returns the most recent N alerts, newest first."""
        return list(self.recent_alerts)[-limit:][::-1]

    def get_alert_count(self):
        return len(self.recent_alerts)

    def load_all_alerts_from_log(self):
        """
        Reads the full persistent log file from disk. Useful for the
        dashboard to show historical alerts beyond what's in memory.
        """
        if not os.path.exists(self.log_file):
            return []

        alerts = []
        with open(self.log_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
        return alerts


if __name__ == "__main__":
    # quick standalone test
    manager = AlertManager()

    fake_attack = {
        "prediction": "ATTACK",
        "confidence": 0.93,
        "attack_probability": 0.93,
        "src_ip": "203.0.113.5",
        "dst_ip": "10.10.1.237",
        "src_port": 4444,
        "dst_port": 22,
        "protocol": "TCP",
    }

    fake_benign = {
        "prediction": "BENIGN",
        "confidence": 0.98,
        "attack_probability": 0.02,
        "src_ip": "8.8.8.8",
        "dst_ip": "10.10.1.237",
        "src_port": 443,
        "dst_port": 50000,
        "protocol": "TCP",
    }

    print("Processing fake attack detection...")
    manager.process_detection(fake_attack)

    print("Processing fake benign detection (should NOT alert)...")
    manager.process_detection(fake_benign)

    print(f"\nTotal alerts in memory: {manager.get_alert_count()}")
    print("Recent alerts:")
    for a in manager.get_recent_alerts():
        print(a)