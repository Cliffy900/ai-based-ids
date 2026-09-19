"""
detection/ensemble.py

Combines the ML binary classifier and the rule-based scan detector into
a single decision per flow, rather than treating them as two parallel,
independent outputs.

Decision rule: a flow is judged ATTACK if EITHER
  - the ML model classifies this specific flow as ATTACK, OR
  - the rule-based scan detector currently flags this flow's source IP
    as actively port-scanning (a signal that persists across flows,
    not tied to this one flow's own statistics).
"""

from detection.detector import Detector
from detection.scan_detector import ScanDetector
from detection.multiclass_detector import MulticlassDetector


class EnsembleDetector:
    def __init__(self, binary_detector: Detector, scan_detector: ScanDetector,
                 multiclass_detector: MulticlassDetector = None):
        self.binary_detector = binary_detector
        self.scan_detector = scan_detector
        self.multiclass_detector = multiclass_detector

    def evaluate(self, flow_features: dict) -> dict:
        ml_result = self.binary_detector.predict(flow_features)

        src_ip = flow_features.get("_src_ip")
        dst_ip = flow_features.get("_dst_ip")

        scan_flagged = False
        if src_ip:
            scan_flagged = self.scan_detector.is_source_currently_flagged(src_ip, dst_ip) \
                or self.scan_detector.is_source_currently_flagged(src_ip)

        contributing_signals = []
        if ml_result["prediction"] == "ATTACK":
            contributing_signals.append("ml_model")
        if scan_flagged:
            contributing_signals.append("rule_based_scan")

        final_prediction = "ATTACK" if contributing_signals else "BENIGN"

        attack_type = None
        type_confidence = None
        if final_prediction == "ATTACK":
            if "ml_model" in contributing_signals and self.multiclass_detector is not None:
                type_result = self.multiclass_detector.predict_type(flow_features)
                attack_type = type_result["attack_type"]
                type_confidence = type_result["type_confidence"]
            elif "rule_based_scan" in contributing_signals:
                attack_type = "Port Scan (rule-based)"

        return {
            "prediction": final_prediction,
            "confidence": ml_result["confidence"],
            "attack_probability": ml_result["attack_probability"],
            "contributing_signals": contributing_signals,
            "attack_type": attack_type,
            "type_confidence": type_confidence,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": flow_features.get("_src_port"),
            "dst_port": flow_features.get("Destination Port"),
            "protocol": flow_features.get("_protocol"),
        }