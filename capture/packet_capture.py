import json
import os
import re
import shutil
import socket
import subprocess
import warnings
from datetime import datetime

warnings.simplefilter("ignore", category=UserWarning)

from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP

from alerts.alert_manager import AlertManager
from detection.detector import Detector
from detection.ensemble import EnsembleDetector
from detection.multiclass_detector import MulticlassDetector
from detection.scan_detector import ScanDetector
from preprocessing.feature_extraction import FlowTracker


# Live capture uses a shorter flow timeout so completed flows can
# be evaluated while packet capture is still running.
LIVE_FLOW_TIMEOUT = 5


scan_detector = ScanDetector(
    window_seconds=10,
    port_threshold=15,
)

tracker = FlowTracker(
    flow_timeout=LIVE_FLOW_TIMEOUT,
)

detector = Detector()
multiclass_detector = MulticlassDetector()

ensemble = EnsembleDetector(
    detector,
    scan_detector,
    multiclass_detector,
)

alert_manager = AlertManager()


def run_scan_test(target_ip, nmap_path=None):
    """
    Launch an Nmap SYN scan against the target IP.

    If nmap_path is not provided, locate Nmap using the operating
    system's PATH. This works on Linux and Windows as long as Nmap
    is installed and available on PATH.
    """
    if nmap_path is None:
        nmap_path = shutil.which("nmap")

    if not nmap_path:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and make sure it is "
            "available on your PATH."
        )

    print(f"Launching nmap scan against {target_ip} ...")

    try:
        subprocess.Popen(
            [nmap_path, "-sS", target_ip]
        )
    except OSError as exc:
        raise RuntimeError(
            f"Failed to launch Nmap using '{nmap_path}': {exc}"
        ) from exc


def get_local_ip():
    """
    Get the local IP address currently used for outbound traffic.

    The UDP socket connection does not send application data. It lets
    the operating system determine which local interface/address it
    would use to reach the destination.
    """
    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    except OSError:
        return "127.0.0.1"

    finally:
        s.close()


def get_default_gateway():
    """
    Detect the default IPv4 gateway in a platform-independent way.

    Linux:
        Reads the default route from `ip route`.

    Windows:
        Parses `ipconfig` output.

    Returns:
        Gateway IP address as a string, or None if it cannot be found.
    """
    if os.name == "nt":
        return _get_windows_gateway()

    return _get_linux_gateway()


def _get_linux_gateway():
    """Read the default IPv4 gateway from the Linux routing table."""
    try:
        output = subprocess.check_output(
            ["ip", "-4", "route"],
            text=True,
            stderr=subprocess.DEVNULL,
        )

    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
    ):
        return None

    for line in output.splitlines():
        match = re.match(
            r"^default via ([\d.]+)",
            line.strip(),
        )

        if match:
            return match.group(1)

    return None


def _get_windows_gateway():
    """Parse the default IPv4 gateway from Windows ipconfig output."""
    try:
        output = subprocess.check_output(
            "ipconfig",
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL,
        )

    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
    ):
        return None

    matches = re.findall(
        r"Default Gateway[.\s]*:\s*([\d.]+)",
        output,
    )

    for gateway in matches:
        if gateway and gateway != "0.0.0.0":
            return gateway

    return None


def get_active_interface():
    """
    Return Scapy's interface currently associated with the default route.

    This avoids hardcoding interface names such as 'Ethernet', 'Wi-Fi',
    or 'eth0'.
    """
    return conf.iface


def evaluate_completed_flows(completed_flows):
    """
    Evaluate newly completed flows through the ensemble detector.

    Returns the detection results so the caller can optionally use
    them for logging or additional processing.
    """
    results = []

    for flow_features in completed_flows:
        result = ensemble.evaluate(flow_features)

        signals = (
            ", ".join(result["contributing_signals"])
            if result["contributing_signals"]
            else "none"
        )

        type_str = (
            f" | type: {result['attack_type']}"
            if result["attack_type"]
            else ""
        )

        print(
            f"\n[LIVE DETECTION] "
            f"{result['prediction']} "
            f"(signals: {signals}) | "
            f"{result['src_ip']}:{result['src_port']} -> "
            f"{result['dst_ip']}:{result['dst_port']} "
            f"[{result['protocol']}]{type_str}"
        )

        alert_manager.process_detection(result)
        results.append(result)

    return results


def process_packet(packet):
    """Convert an IP packet into flow information and update detectors."""
    if not packet.haslayer(IP):
        return None

    proto_name = "OTHER"
    sport = dport = None

    header_length = packet[IP].ihl * 4
    tcp_flags = None

    if packet.haslayer(TCP):
        proto_name = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport

        header_length += packet[TCP].dataofs * 4
        tcp_flags = str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        proto_name = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

        info = {
        "timestamp": float(packet.time),
        "captured_at": datetime.now().isoformat(),
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "protocol": proto_name,
        "sport": sport,
        "dport": dport,
        "length": len(packet),
        "header_length": header_length,
        "tcp_flags": tcp_flags,
    }

    print(
        f"[{info['captured_at']}] "
        f"{info['src']}:{info['sport']} -> "
        f"{info['dst']}:{info['dport']} | "
        f"{info['protocol']} | "
        f"{info['length']} bytes"
    )

    completed_flows = tracker.process_packet_info(info)

    if completed_flows:
        evaluate_completed_flows(completed_flows)

    scan_alert = scan_detector.record_packet(
        src_ip=info["src"],
        dst_ip=info["dst"],
        dst_port=info["dport"],
    )

    if scan_alert:
        print(
            f"\n🚨 PORT SCAN DETECTED | "
            f"{scan_alert['src_ip']} contacted "
            f"{scan_alert['distinct_ports_contacted']} distinct ports "
            f"on {scan_alert['target_ip']} within "
            f"{scan_alert['window_seconds']}s\n"
        )

        alert_manager.recent_alerts.append(
            scan_alert
        )

        with open(
            alert_manager.log_file,
            "a",
        ) as f:
            f.write(
                json.dumps(scan_alert) + "\n"
            )

    return info


def start_capture(
    interface=None,
    packet_count=0,
    bpf_filter=None,
    timeout=None,
):
    """
    Start packet capture.

    Args:
        interface: Scapy interface name. None uses the default interface.
        packet_count: Number of packets to capture. 0 means unlimited.
        bpf_filter: Optional BPF filter such as 'tcp or udp'.
        timeout: Optional maximum capture duration in seconds.
    """
    sniff(
        iface=interface,
        prn=process_packet,
        count=packet_count,
        filter=bpf_filter,
        timeout=timeout,
        store=False,
    )

if __name__ == "__main__":
    import time
    import threading

    local_ip = get_local_ip()
    print(f"Detected local IP: {local_ip}")

    active_iface = get_active_interface()
    print(f"Detected active interface: {active_iface}")

    target_ip = get_default_gateway()

    if not target_ip:
        raise RuntimeError(
            "Could not detect the default gateway. "
            "Check your network connection and routing table."
        )

    print(f"Detected target IP (gateway): {target_ip}")

    # Start packet capture before launching the scan so the
    # scanner's traffic is not missed.
    capture_thread = threading.Thread(
        target=start_capture,
        kwargs={
            "interface": active_iface,
            "packet_count": 0,
            "bpf_filter": f"host {target_ip}",
            "timeout": 15,
        },
    )

    print("Starting packet capture...")
    capture_thread.start()

    # Give Scapy a moment to begin sniffing.
    time.sleep(1)

    # Launch the test scan while packet capture is already running.
    run_scan_test(target_ip=target_ip)

    # Wait for packet capture to finish.
    capture_thread.join()

    # Evaluate any flows that completed but were not evaluated live.
    completed_flows = tracker.get_completed_flows()

    if completed_flows:
        print(
            f"\n--- {len(completed_flows)} COMPLETED FLOWS AFTER CAPTURE ---"
        )
        evaluate_completed_flows(completed_flows)

    # Evaluate flows that were still active when capture stopped.
    active_flows = tracker.get_active_flow_features()

    if active_flows:
        print(
            f"\n--- {len(active_flows)} ACTIVE FLOWS AFTER CAPTURE ---"
        )
        evaluate_completed_flows(active_flows)

    if not completed_flows and not active_flows:
        print("\n--- NO FLOWS REMAINED AFTER CAPTURE ---")