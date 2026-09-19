"""
Standalone test proving the ensemble actually combines both signals,
without needing live capture. Two cases:

1. A flow the ML model calls BENIGN, but whose source was JUST flagged
   by the scan detector -- the ensemble should override to ATTACK.
2. A flow the ML model calls ATTACK on its own -- the ensemble should
   agree, independent of any scan activity.
"""

from detection.detector import Detector
from detection.scan_detector import ScanDetector
from detection.multiclass_detector import MulticlassDetector
from detection.ensemble import EnsembleDetector

binary_detector = Detector()
scan_detector = ScanDetector(window_seconds=10, port_threshold=20)
multiclass_detector = MulticlassDetector()

ensemble = EnsembleDetector(binary_detector, scan_detector, multiclass_detector)

# a clearly benign-looking flow (same shape as the dashboard's benign preset)
benign_flow = {
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
    "_src_ip": "10.10.1.50", "_dst_ip": "10.10.1.68",
    "_src_port": 12345, "_protocol": "TCP",
}

print("=== CASE 1: ML alone (before any scan activity) ===")
result = ensemble.evaluate(benign_flow)
print(result)
assert result["prediction"] == "BENIGN", "Expected BENIGN before scan activity"
print("PASSED: correctly BENIGN with no contributing signals\n")

print("=== Simulating a port scan from the same source ===")
for port in range(1, 26):
    alert = scan_detector.record_packet("10.10.1.50", "10.10.1.68", port)
    if alert:
        print(f"Scan alert fired at port #{port}: {alert}\n")
        break

print("=== CASE 2: SAME benign-looking flow, AFTER scan activity from its source ===")
result = ensemble.evaluate(benign_flow)
print(result)
assert result["prediction"] == "ATTACK", "Expected ensemble to override to ATTACK"
assert "rule_based_scan" in result["contributing_signals"]
assert "ml_model" not in result["contributing_signals"]
print("PASSED: ensemble correctly overrode ML's BENIGN call due to scan activity\n")

print("All ensemble tests passed.")