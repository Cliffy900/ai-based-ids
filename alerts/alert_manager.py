"""
alerts/alert_manager.py

Handles attack alerts produced by the ensemble detector.

Responsibilities:
- filter detections using the configured ML probability threshold
- preserve ensemble detection information
- prevent repeated flows from creating duplicate alerts
- print alerts to the console
- store alerts in memory for the dashboard
- persist alerts as JSON Lines
- restore alert state after application restarts
"""

import os
import json
from datetime import datetime, timedelta
from collections import deque


ALERTS_LOG_DIR = "alerts/logs"
ALERTS_LOG_FILE = os.path.join(ALERTS_LOG_DIR, "alerts.jsonl")

# How many recent alerts to keep in memory for dashboard access.
MAX_RECENT_ALERTS = 500

# ML detections below this probability are not alerted.
ALERT_THRESHOLD = 0.5

# Repeated detections belonging to the same incident are suppressed
# during this period.
INCIDENT_COOLDOWN_SECONDS = 30


class AlertManager:
    def __init__(
        self,
        log_file=ALERTS_LOG_FILE,
        alert_threshold=ALERT_THRESHOLD,
        incident_cooldown=INCIDENT_COOLDOWN_SECONDS,
    ):
        self.log_file = log_file
        self.alert_threshold = alert_threshold
        self.incident_cooldown = incident_cooldown

        self.recent_alerts = deque(maxlen=MAX_RECENT_ALERTS)

        # Maps an incident key to the time its last alert was raised.
        self.active_incidents = {}

        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        # Restore persisted state so alert history and incident
        # deduplication survive application restarts.
        self._restore_state()

    def process_detection(self, detection_result: dict):
        """
        Process one detection result from EnsembleDetector.

        Returns:
            True if a new alert was raised.
            False if the detection was benign, below threshold,
            or suppressed as a duplicate incident.
        """

        if detection_result.get("prediction") != "ATTACK":
            return False

        contributing_signals = detection_result.get(
            "contributing_signals", []
        )

        attack_probability = detection_result.get(
            "attack_probability", 0.0
        )

        # ML threshold applies to ML-driven detections.
        #
        # A rule-based scan is already an independent detection signal,
        # so it should not be blocked simply because the ML model gave
        # it a low attack probability.
        ml_signal = "ml_model" in contributing_signals
        rule_based_signal = "rule_based_scan" in contributing_signals

        if ml_signal and not rule_based_signal:
            if attack_probability < self.alert_threshold:
                return False

        # If neither signal is present, do not create an alert.
        if not ml_signal and not rule_based_signal:
            return False

        attack_type = detection_result.get("attack_type")

        # Multiple flows from the same source to the same destination
        # with the same attack type are treated as one incident during
        # the cooldown period.
        incident_key = (
            detection_result.get("src_ip"),
            detection_result.get("dst_ip"),
            attack_type or "Unknown",
        )

        if self._is_duplicate_incident(incident_key):
            return False

        alert = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": detection_result.get("src_ip"),
            "dst_ip": detection_result.get("dst_ip"),
            "src_port": detection_result.get("src_port"),
            "dst_port": detection_result.get("dst_port"),
            "protocol": detection_result.get("protocol"),
            "attack_probability": attack_probability,
            "confidence": detection_result.get("confidence"),
            "attack_type": attack_type,
            "type_confidence": detection_result.get("type_confidence"),
            "contributing_signals": contributing_signals,
            "incident_key": incident_key,
        }

        self._raise_alert(alert)

        self.active_incidents[incident_key] = datetime.now()

        return True

    def _restore_state(self):
        """
        Restore recent alerts and active incident cooldowns from disk.

        Alerts older than the configured incident cooldown are kept in
        recent_alerts for dashboard history, but they are not restored
        into active_incidents because their cooldown has expired.
        """

        if not os.path.exists(self.log_file):
            return

        now = datetime.now()

        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        alert = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    self.recent_alerts.append(alert)

                    timestamp = alert.get("timestamp")

                    if not timestamp:
                        continue

                    try:
                        alert_time = datetime.fromisoformat(timestamp)
                    except (TypeError, ValueError):
                        continue

                    elapsed = now - alert_time

                    if elapsed < timedelta(seconds=self.incident_cooldown):
                        incident_key = alert.get("incident_key")

                        if incident_key:
                            self.active_incidents[
                                tuple(incident_key)
                            ] = alert_time

        except OSError:
            # If the log cannot be read, start with empty in-memory state.
            return

    def _is_duplicate_incident(self, incident_key):
        """
        Returns True when an incident was already alerted recently.
        """

        last_alert_time = self.active_incidents.get(incident_key)

        if last_alert_time is None:
            return False

        elapsed = datetime.now() - last_alert_time

        if elapsed >= timedelta(seconds=self.incident_cooldown):
            del self.active_incidents[incident_key]
            return False

        return True

    def _raise_alert(self, alert: dict):
        """
        Print and persist a new alert.
        """

        signals = ", ".join(alert["contributing_signals"])
        attack_type = alert.get("attack_type") or "Unknown"

        print(
            f"\n🚨 ALERT [{alert['timestamp']}] "
            f"{attack_type}\n"
            f"   Source: {alert['src_ip']}:{alert['src_port']} "
            f"-> {alert['dst_ip']}:{alert['dst_port']} "
            f"[{alert['protocol']}]\n"
            f"   Signals: {signals}\n"
            f"   ML attack probability: "
            f"{alert['attack_probability']:.2%}\n"
        )

        # Store in memory for dashboard access.
        self.recent_alerts.append(alert)

        # Persist as JSON Lines.
        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def get_recent_alerts(self, limit=50):
        """Returns the most recent N alerts, newest first."""
        return list(self.recent_alerts)[-limit:][::-1]

    def get_alert_count(self):
        """Returns the number of alerts currently stored in memory."""
        return len(self.recent_alerts)

    def load_all_alerts_from_log(self):
        """
        Reads the full persistent alert log from disk.

        Useful for the dashboard to display historical alerts beyond
        what is currently stored in memory.
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
    # Quick standalone test.
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
        "contributing_signals": ["ml_model"],
        "attack_type": "Brute Force",
        "type_confidence": 0.91,
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
        "contributing_signals": [],
        "attack_type": None,
        "type_confidence": None,
    }

    fake_scan = {
        "prediction": "ATTACK",
        "confidence": 0.40,
        "attack_probability": 0.10,
        "src_ip": "192.0.2.50",
        "dst_ip": "10.10.1.237",
        "src_port": 4444,
        "dst_port": 22,
        "protocol": "TCP",
        "contributing_signals": ["rule_based_scan"],
        "attack_type": "Port Scan (rule-based)",
        "type_confidence": None,
    }

    print("Processing fake ML attack...")
    manager.process_detection(fake_attack)

    print("\nProcessing duplicate ML attack...")
    manager.process_detection(fake_attack)

    print("\nProcessing fake benign detection...")
    manager.process_detection(fake_benign)

    print("\nProcessing fake rule-based scan...")
    manager.process_detection(fake_scan)

    print("\nProcessing duplicate rule-based scan...")
    manager.process_detection(fake_scan)

    print(f"\nTotal alerts in memory: {manager.get_alert_count()}")

    print("\nRecent alerts:")
    for alert in manager.get_recent_alerts():
        print(alert)