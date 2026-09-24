"""
Tests for AlertManager alert persistence and incident deduplication.
"""

import json
import tempfile
from datetime import datetime

from alerts.alert_manager import AlertManager


FAKE_ATTACK = {
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


def test_alert_persists_across_restart():
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = f"{temp_dir}/alerts.jsonl"

        # First AlertManager instance creates an alert.
        manager = AlertManager(
            log_file=log_file,
            incident_cooldown=30,
        )

        created = manager.process_detection(FAKE_ATTACK)

        assert created is True
        assert manager.get_alert_count() == 1

        # Simulate an application restart.
        restarted_manager = AlertManager(
            log_file=log_file,
            incident_cooldown=30,
        )

        # The previous alert should have been restored.
        assert restarted_manager.get_alert_count() == 1

        # The same incident should still be inside its cooldown.
        duplicate_created = restarted_manager.process_detection(
            FAKE_ATTACK
        )

        assert duplicate_created is False
        assert restarted_manager.get_alert_count() == 1

        print("PASSED: alert state survived restart")


def test_corrupt_log_lines_are_ignored():
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = f"{temp_dir}/alerts.jsonl"

        with open(log_file, "w") as f:
            # Invalid JSON should not crash AlertManager.
            f.write("this is not valid JSON\n")

            valid_alert = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": "203.0.113.5",
                "dst_ip": "10.10.1.237",
                "attack_type": "Brute Force",
                "incident_key": [
                    "203.0.113.5",
                    "10.10.1.237",
                    "Brute Force",
                ],
            }

            f.write(json.dumps(valid_alert) + "\n")

        manager = AlertManager(log_file=log_file)

        assert manager.get_alert_count() == 1

        print("PASSED: corrupt log lines are ignored")


if __name__ == "__main__":
    test_alert_persists_across_restart()
    test_corrupt_log_lines_are_ignored()

    print("\nAll AlertManager persistence tests passed.")