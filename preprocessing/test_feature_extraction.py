"""
Tests for live flow aggregation and timestamp-based feature extraction.
"""

from preprocessing.feature_extraction import FlowTracker


def make_packet(
    timestamp,
    src="10.0.0.1",
    dst="10.0.0.2",
    sport=12345,
    dport=80,
):
    """
    Create a test packet with a controlled capture timestamp.
    """
    return {
        "timestamp": timestamp,
        "src": src,
        "dst": dst,
        "protocol": "TCP",
        "sport": sport,
        "dport": dport,
        "length": 100,
        "header_length": 40,
        "tcp_flags": "A",
    }


def test_flow_duration_uses_packet_timestamps():
    """
    Flow duration should be calculated from packet capture
    timestamps rather than the system clock.
    """
    tracker = FlowTracker(flow_timeout=60)

    tracker.process_packet_info(
        make_packet(100.0)
    )

    tracker.process_packet_info(
        make_packet(102.0)
    )

    features = tracker.get_active_flow_features()[0]

    assert features["Flow Duration"] == 2.0


def test_flow_iat_uses_packet_timestamps():
    """
    Flow IAT statistics should use the timestamps of captured
    packets.
    """
    tracker = FlowTracker(flow_timeout=60)

    tracker.process_packet_info(
        make_packet(100.0)
    )

    tracker.process_packet_info(
        make_packet(101.5)
    )

    tracker.process_packet_info(
        make_packet(104.0)
    )

    features = tracker.get_active_flow_features()[0]

    assert features["Flow IAT Mean"] == 2.0
    assert features["Flow IAT Max"] == 2.5
    assert features["Flow IAT Min"] == 1.5


def test_flow_expiration_uses_packet_timestamps():
    """
    A flow should expire when the capture timeline advances
    beyond the configured flow timeout.
    """
    tracker = FlowTracker(flow_timeout=5)

    # First flow packet at timestamp 100.
    tracker.process_packet_info(
        make_packet(100.0)
    )

    # A packet at timestamp 106 advances the capture timeline
    # by six seconds, exceeding the five-second timeout.
    completed = tracker.process_packet_info(
        make_packet(
            106.0,
            src="10.0.0.3",
            dst="10.0.0.4",
        )
    )

    assert len(completed) == 1
    assert completed[0]["_src_ip"] == "10.0.0.1"
    assert completed[0]["_dst_ip"] == "10.0.0.2"


def test_packet_statistics_remain_correct():
    """
    Forward and backward packets belonging to the same flow
    should be counted in the correct directions.
    """
    tracker = FlowTracker(flow_timeout=60)

    # Original direction:
    # 10.0.0.1:12345 -> 10.0.0.2:80
    tracker.process_packet_info(
        make_packet(100.0)
    )

    # Reverse direction of the same flow:
    # 10.0.0.2:80 -> 10.0.0.1:12345
    tracker.process_packet_info(
        make_packet(
            101.0,
            src="10.0.0.2",
            dst="10.0.0.1",
            sport=80,
            dport=12345,
        )
    )

    features = tracker.get_active_flow_features()[0]

    assert features["Total Fwd Packets"] == 1
    assert features["Total Backward Packets"] == 1

    assert features["Total Length of Fwd Packets"] == 100
    assert features["Total Length of Bwd Packets"] == 100

    assert features["ACK Flag Count"] == 2