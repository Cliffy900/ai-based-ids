"""
Quick standalone test to verify ScanDetector triggers correctly,
without needing a live capture or nmap.
"""

from detection.scan_detector import ScanDetector
import time

detector = ScanDetector(window_seconds=10, port_threshold=20)

src_ip = "10.10.1.131"
target_ip = "10.10.1.68"

print("Simulating 25 rapid port-scan packets...")

alert_fired = None
for port in range(1, 26):  # 25 distinct ports
    alert = detector.record_packet(src_ip, target_ip, port, timestamp=time.time())
    if alert:
        alert_fired = alert
        print(f"ALERT FIRED at port #{port}: {alert}")
        break

if not alert_fired:
    print("NO ALERT FIRED — something is wrong with the detector logic.")
else:
    print("\nScanDetector is working correctly.")