"""
detection/scan_detector.py

Host-level rule-based detection to catch port scans that per-flow
ML classification misses. Tracks, per source IP, how many distinct
destination ports were contacted within a rolling time window, and
flags the source if that count crosses a threshold.

This complements the ML-based Detector: the ML model looks at
individual flow statistics (packet sizes, timing, flags), while this
module looks at *behavior across many flows* from the same source --
exactly the signal a fast port scan produces but a single flow does not.
"""

import time
from collections import defaultdict, deque


class ScanDetector:
    def __init__(self, window_seconds=10, port_threshold=20):
        """
        window_seconds: how far back to look when counting distinct ports
        port_threshold: how many distinct destination ports within the
                        window triggers a scan alert
        """
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold

        # src_ip -> deque of (timestamp, dst_ip, dst_port)
        self.activity = defaultdict(deque)

        # (src_ip, target_ip) -> last time we already alerted, to avoid
        # spamming a fresh alert on every subsequent packet
        self.last_alerted = {}
        self.realert_cooldown = 30  # seconds before re-alerting the same pair

    def is_source_currently_flagged(self, src_ip, target_ip=None):
        """
        Non-mutating check: has this src_ip (optionally against this
        specific target_ip) raised a scan alert recently -- within the
        current re-alert cooldown window? Used by the ensemble to ask
        "is this source considered a scanner right now?" without
        triggering the packet-counting logic in record_packet().
        """
        now = time.time()
        for (s_ip, t_ip), last_ts in self.last_alerted.items():
            if s_ip != src_ip:
                continue
            if target_ip is not None and t_ip != target_ip:
                continue
            if now - last_ts <= self.realert_cooldown:
                return True
        return False

    def record_packet(self, src_ip, dst_ip, dst_port, timestamp=None):
        """
        Call this for every captured packet (not just completed flows).
        Returns an alert dict if this packet pushed the source over the
        threshold, otherwise None.
        """
        if dst_port is None:
            return None

        timestamp = timestamp or time.time()

        history = self.activity[src_ip]
        history.append((timestamp, dst_ip, dst_port))

        # drop entries older than the window
        cutoff = timestamp - self.window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        # count distinct ports per target destination
        ports_per_target = defaultdict(set)
        for _, d_ip, port in history:
            ports_per_target[d_ip].add(port)

        for target_ip, ports in ports_per_target.items():
            if len(ports) >= self.port_threshold:
                now = timestamp
                last = self.last_alerted.get((src_ip, target_ip), 0)
                if now - last >= self.realert_cooldown:
                    self.last_alerted[(src_ip, target_ip)] = now
                    return {
                        "type": "PORT_SCAN",
                        "src_ip": src_ip,
                        "target_ip": target_ip,
                        "distinct_ports_contacted": len(ports),
                        "window_seconds": self.window_seconds,
                        "timestamp": now,
                    }

        return None

    def get_completed_flows(self):
        """
        Not used internally by ScanDetector itself -- present for
        interface symmetry with FlowTracker where callers expect a
        get_completed_flows()-style method. Returns an empty list since
        ScanDetector doesn't track flows, only per-packet port activity.
        """
        return []