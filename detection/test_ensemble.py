"""
Standalone test proving the ensemble combines both detection signals.

Three cases are tested:

1. ML-only ATTACK:
   A deterministic fake ML detector reports ATTACK. The ensemble
   should pass that signal through.

2. ML BENIGN before scan activity:
   The real ML detector evaluates a benign-looking flow. With no
   scan activity, the ensemble should report BENIGN.

3. Rule-based scan override:
   The same benign-looking flow is evaluated after its source IP
   has triggered the scan detector. The ensemble should report ATTACK
   because of the rule-based scan signal.
"""

from detection.detector import Detector
from detection.scan_detector import ScanDetector
from detection.multiclass_detector import MulticlassDetector
from detection.ensemble import EnsembleDetector


class FakeAttackDetector:
    """
    Deterministic ML detector used to test the ensemble's ML-only path.

    This avoids making the test depend on whether a hand-written
    synthetic flow happens to cross the trained Random Forest's
    decision boundary.
    """

    def predict(self, flow_features):
        return {
            "prediction": "ATTACK",
            "confidence": 0.99,
            "attack_probability": 0.99,
            "src_ip": flow_features.get("_src_ip"),
            "dst_ip": flow_features.get("_dst_ip"),
            "src_port": flow_features.get("_src_port"),
            "dst_port": flow_features.get("Destination Port"),
            "protocol": flow_features.get("_protocol"),
        }


# Real detectors used for the normal and scan-override cases.
binary_detector = Detector()
scan_detector = ScanDetector(window_seconds=10, port_threshold=20)
multiclass_detector = MulticlassDetector()

ensemble = EnsembleDetector(
    binary_detector,
    scan_detector,
    multiclass_detector,
)


# A clearly benign-looking flow (same shape as the dashboard's
# benign preset).
benign_flow = {
    "Destination Port": 54865,
    "Flow Duration": 3,
    "Total Fwd Packets": 2,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 12,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Max": 6,
    "Fwd Packet Length Min": 6,
    "Fwd Packet Length Mean": 6.0,
    "Fwd Packet Length Std": 0.0,
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0.0,
    "Bwd Packet Length Std": 0.0,
    "Flow Bytes/s": 4000000.0,
    "Flow Packets/s": 666666.6667,
    "Flow IAT Mean": 3.0,
    "Flow IAT Std": 0.0,
    "Flow IAT Max": 3,
    "Flow IAT Min": 3,
    "Fwd PSH Flags": 0,
    "SYN Flag Count": 0,
    "RST Flag Count": 0,
    "ACK Flag Count": 1,
    "FIN Flag Count": 0,
    "Fwd Header Length": 40,
    "Bwd Header Length": 0,
    "Min Packet Length": 6,
    "Max Packet Length": 6,
    "Packet Length Mean": 6.0,
    "Packet Length Std": 0.0,
    "_src_ip": "10.10.1.50",
    "_dst_ip": "10.10.1.68",
    "_src_port": 12345,
    "_protocol": "TCP",
}


print("=== CASE 1: ML-only attack ===")

ml_attack_ensemble = EnsembleDetector(
    FakeAttackDetector(),
    scan_detector,
    multiclass_detector=None,
)

result = ml_attack_ensemble.evaluate(benign_flow)

print(result)

assert result["prediction"] == "ATTACK", (
    "Expected ensemble to report ATTACK from ML signal"
)

assert "ml_model" in result["contributing_signals"], (
    "Expected ml_model to be a contributing signal"
)

assert "rule_based_scan" not in result["contributing_signals"], (
    "Did not expect a scan signal in the ML-only test"
)

assert result["attack_type"] is None, (
    "Expected no attack type because no multiclass detector was supplied"
)

print("PASSED: ensemble correctly accepted the ML ATTACK signal\n")


print("=== CASE 2: ML-only benign flow before scan activity ===")

result = ensemble.evaluate(benign_flow)

print(result)

assert result["prediction"] == "BENIGN", (
    "Expected BENIGN before scan activity"
)

assert result["contributing_signals"] == [], (
    "Expected no contributing signals before scan activity"
)

print("PASSED: correctly BENIGN with no contributing signals\n")


print("=== Simulating a port scan from the same source ===")

for port in range(1, 26):
    alert = scan_detector.record_packet(
        "10.10.1.50",
        "10.10.1.68",
        port,
    )

    if alert:
        print(f"Scan alert fired at port #{port}: {alert}\n")
        break


print("=== CASE 3: Rule-based scan override ===")

result = ensemble.evaluate(benign_flow)

print(result)

assert result["prediction"] == "ATTACK", (
    "Expected ensemble to override ML BENIGN result to ATTACK"
)

assert "rule_based_scan" in result["contributing_signals"], (
    "Expected rule_based_scan to be a contributing signal"
)

assert "ml_model" not in result["contributing_signals"], (
    "Expected ML to remain BENIGN in this test"
)

assert result["attack_type"] == "Port Scan (rule-based)", (
    "Expected rule-based port scan attack type"
)

print("PASSED: ensemble correctly overrode ML BENIGN due to scan activity\n")


print("All ensemble tests passed.")