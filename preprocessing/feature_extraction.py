"""
preprocessing/feature_extraction.py

Aggregates raw packets into flows and extracts statistical features
matching a subset of the CICIDS2017 feature schema.

The FlowTracker can return newly completed flows immediately when
they expire, allowing live capture to perform near-real-time
flow-based detection.

Flow timing is based on packet capture timestamps rather than the
machine's wall-clock time. This makes flow duration, IAT statistics,
and expiration consistent with the actual captured traffic timeline.
"""

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

    start_time: float
    last_seen: float

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

    def add_packet(
        self,
        length,
        header_length,
        direction,
        timestamp,
        tcp_flags=None,
    ):
        """
        Add a packet to the flow using its capture timestamp.
        """
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
        """
        Return the duration of the flow based on packet timestamps.
        """
        return max(
            self.last_seen - self.start_time,
            1e-6,
        )

    def _iat_stats(self):
        """
        Calculate inter-arrival-time statistics using packet
        capture timestamps.
        """
        ts = sorted(self.all_timestamps)

        if len(ts) < 2:
            return {
                "mean": 0.0,
                "std": 0.0,
                "max": 0.0,
                "min": 0.0,
            }

        iats = [
            t2 - t1
            for t1, t2 in zip(ts[:-1], ts[1:])
        ]

        return {
            "mean": _safe_mean(iats),
            "std": _safe_std(iats),
            "max": max(iats),
            "min": min(iats),
        }

    def extract_features(self):
        """
        Extract the flow features used by the IDS model.
        """
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

            "Fwd Packet Length Max": (
                max(fwd) if fwd else 0
            ),
            "Fwd Packet Length Min": (
                min(fwd) if fwd else 0
            ),
            "Fwd Packet Length Mean": _safe_mean(fwd),
            "Fwd Packet Length Std": _safe_std(fwd),

            "Bwd Packet Length Max": (
                max(bwd) if bwd else 0
            ),
            "Bwd Packet Length Min": (
                min(bwd) if bwd else 0
            ),
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

            "Fwd Header Length": sum(
                self.fwd_header_lengths
            ),
            "Bwd Header Length": sum(
                self.bwd_header_lengths
            ),

            "Min Packet Length": (
                min(all_pkts) if all_pkts else 0
            ),
            "Max Packet Length": (
                max(all_pkts) if all_pkts else 0
            ),
            "Packet Length Mean": _safe_mean(all_pkts),
            "Packet Length Std": _safe_std(all_pkts),

            # Internal metadata used by the detection pipeline.
            "_src_ip": self.src_ip,
            "_dst_ip": self.dst_ip,
            "_src_port": self.src_port,
            "_protocol": self.protocol,
        }


class FlowTracker:
    """
    Tracks active network flows and expires them based on
    packet capture timestamps.
    """

    def __init__(self, flow_timeout=FLOW_TIMEOUT):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self._completed = []

    def _get_flow_key(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    ):
        """
        Create a bidirectional flow key.

        Traffic between the same two endpoints belongs to the same
        flow regardless of which direction the packet travels.
        """
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            )

        return (
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            protocol,
        )

    def process_packet_info(self, packet_info):
        """
        Add a packet to its flow and return any flows that
        expired because of inactivity.

        The packet's capture timestamp is used for all flow timing.
        """

        src_ip = packet_info["src"]
        dst_ip = packet_info["dst"]

        sport = packet_info.get("sport") or 0
        dport = packet_info.get("dport") or 0

        protocol = packet_info["protocol"]
        length = packet_info["length"]

        header_length = packet_info.get(
            "header_length",
            0,
        )

        tcp_flags = packet_info.get(
            "tcp_flags"
        )

        # Use the timestamp recorded by Scapy during capture.
        # Do not use time.time() here because that measures when
        # the program processes the packet rather than when the
        # packet was captured.
        if "timestamp" not in packet_info:
            raise ValueError(
                "Packet information must contain a 'timestamp'."
            )

        timestamp = float(packet_info["timestamp"])

        # Expire stale flows BEFORE processing the current packet.
        #
        # This is important when a packet arrives after a long gap.
        # The previous flow should be completed before this packet
        # starts a new flow.
        completed = self._expire_flows(timestamp)

        key = self._get_flow_key(
            src_ip,
            dst_ip,
            sport,
            dport,
            protocol,
        )

        if key not in self.flows:
            self.flows[key] = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                protocol=protocol,
                start_time=timestamp,
                last_seen=timestamp,
            )

        flow = self.flows[key]

        direction = (
            "fwd"
            if (src_ip, sport)
            == (flow.src_ip, flow.src_port)
            else "bwd"
        )

        flow.add_packet(
            length,
            header_length,
            direction,
            timestamp,
            tcp_flags,
        )

        return completed

    def _expire_flows(self, current_timestamp):
        """
        Remove inactive flows using the supplied packet capture
        timestamp.

        A flow is considered expired when the time since its last
        captured packet exceeds flow_timeout.
        """
        expired_keys = [
            key
            for key, flow in self.flows.items()
            if current_timestamp - flow.last_seen
            > self.flow_timeout
        ]

        completed = []

        for key in expired_keys:
            flow = self.flows.pop(key)

            features = flow.extract_features()

            self._completed.append(features)
            completed.append(features)

        return completed

    def get_completed_flows(self):
        """
        Return completed flows that have not yet been retrieved.
        """
        completed = self._completed
        self._completed = []

        return completed

    def get_active_flow_features(self):
        """
        Return features for flows that are still active.
        """
        return [
            flow.extract_features()
            for flow in self.flows.values()
        ]