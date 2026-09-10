"""
preprocessing/feature_extraction.py

Aggregates raw packets into flows and extracts statistical features
matching a subset of the CICIDS2017 feature schema (column names match
the CSV exactly, so train_model.py and live capture stay aligned).
"""

import time
import statistics
from dataclasses import dataclass, field


FLOW_TIMEOUT = 60  # seconds of inactivity before a flow is considered closed


def _safe_mean(values):
    return statistics.mean(values) if values else 0.0


def _safe_std(values):
    return statistics.pstdev(values) if len(values) > 1 else 0.0


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    fwd_lengths: list = field(default_factory=list)
    bwd_lengths: list = field(default_factory=list)

    fwd_header_lengths: list = field(default_factory=list)
    bwd_header_lengths: list = field(default_factory=list)

    all_timestamps: list = field(default_factory=list)

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    fwd_psh_count: int = 0

    def add_packet(self, length, header_length, direction, timestamp, tcp_flags=None):
        self.last_seen = timestamp
        self.all_timestamps.append(timestamp)

        if direction == "fwd":
            self.fwd_lengths.append(length)
            self.fwd_header_lengths.append(header_length)
        else:
            self.bwd_lengths.append(length)
            self.bwd_header_lengths.append(header_length)

        if tcp_flags:
            if "S" in tcp_flags:
                self.syn_count += 1
            if "A" in tcp_flags:
                self.ack_count += 1
            if "F" in tcp_flags:
                self.fin_count += 1
            if "R" in tcp_flags:
                self.rst_count += 1
            if "P" in tcp_flags:
                self.psh_count += 1
                if direction == "fwd":
                    self.fwd_psh_count += 1

    def duration(self):
        return max(self.last_seen - self.start_time, 1e-6)

    def _iat_stats(self):
        ts = sorted(self.all_timestamps)
        if len(ts) < 2:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
        iats = [t2 - t1 for t1, t2 in zip(ts[:-1], ts[1:])]
        return {
            "mean": _safe_mean(iats),
            "std": _safe_std(iats),
            "max": max(iats),
            "min": min(iats),
        }

    def extract_features(self):
        fwd = self.fwd_lengths
        bwd = self.bwd_lengths
        all_pkts = fwd + bwd
        duration = self.duration()
        iat = self._iat_stats()

        total_fwd_bytes = sum(fwd)
        total_bwd_bytes = sum(bwd)
        total_bytes = total_fwd_bytes + total_bwd_bytes

        return {
            "Destination Port": self.dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": len(fwd),
            "Total Backward Packets": len(bwd),
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,

            "Fwd Packet Length Max": max(fwd) if fwd else 0,
            "Fwd Packet Length Min": min(fwd) if fwd else 0,
            "Fwd Packet Length Mean": _safe_mean(fwd),
            "Fwd Packet Length Std": _safe_std(fwd),

            "Bwd Packet Length Max": max(bwd) if bwd else 0,
            "Bwd Packet Length Min": min(bwd) if bwd else 0,
            "Bwd Packet Length Mean": _safe_mean(bwd),
            "Bwd Packet Length Std": _safe_std(bwd),

            "Flow Bytes/s": total_bytes / duration,
            "Flow Packets/s": len(all_pkts) / duration,

            "Flow IAT Mean": iat["mean"],
            "Flow IAT Std": iat["std"],
            "Flow IAT Max": iat["max"],
            "Flow IAT Min": iat["min"],

            "Fwd PSH Flags": self.fwd_psh_count,
            "SYN Flag Count": self.syn_count,
            "RST Flag Count": self.rst_count,
            "ACK Flag Count": self.ack_count,
            "FIN Flag Count": self.fin_count,

            "Fwd Header Length": sum(self.fwd_header_lengths),
            "Bwd Header Length": sum(self.bwd_header_lengths),

            "Min Packet Length": min(all_pkts) if all_pkts else 0,
            "Max Packet Length": max(all_pkts) if all_pkts else 0,
            "Packet Length Mean": _safe_mean(all_pkts),
            "Packet Length Std": _safe_std(all_pkts),

            "_src_ip": self.src_ip,
            "_dst_ip": self.dst_ip,
            "_src_port": self.src_port,
            "_protocol": self.protocol,
        }


class FlowTracker:
    def __init__(self, flow_timeout=FLOW_TIMEOUT):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self._completed = []

    def _get_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)

    def process_packet_info(self, packet_info):
        src_ip = packet_info["src"]
        dst_ip = packet_info["dst"]
        sport = packet_info.get("sport") or 0
        dport = packet_info.get("dport") or 0
        protocol = packet_info["protocol"]
        length = packet_info["length"]
        header_length = packet_info.get("header_length", 0)
        tcp_flags = packet_info.get("tcp_flags")
        timestamp = time.time()

        key = self._get_flow_key(src_ip, dst_ip, sport, dport, protocol)

        if key not in self.flows:
            self.flows[key] = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                protocol=protocol,
            )

        flow = self.flows[key]
        direction = "fwd" if (src_ip, sport) == (flow.src_ip, flow.src_port) else "bwd"
        flow.add_packet(length, header_length, direction, timestamp, tcp_flags)

        self._expire_flows()

    def _expire_flows(self):
        now = time.time()
        expired_keys = [
            k for k, f in self.flows.items()
            if now - f.last_seen > self.flow_timeout
        ]
        for k in expired_keys:
            self._completed.append(self.flows.pop(k).extract_features())

    def get_completed_flows(self):
        completed = self._completed
        self._completed = []
        return completed

    def get_active_flow_features(self):
        return [f.extract_features() for f in self.flows.values()]