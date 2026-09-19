import warnings
warnings.simplefilter("ignore", category=UserWarning)
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from detection.scan_detector import ScanDetector

scan_detector = ScanDetector(window_seconds=10, port_threshold=15)

from preprocessing.feature_extraction import FlowTracker
from detection.detector import Detector
from detection.multiclass_detector import MulticlassDetector
from detection.ensemble import EnsembleDetector
from alerts.alert_manager import AlertManager
import json
import subprocess
import re

def run_scan_test(target_ip, nmap_path=r"C:\Program Files (x86)\Nmap\nmap.exe"):
    print(f"Launching nmap scan against {target_ip} ...")
    subprocess.Popen([nmap_path, "-sS", target_ip])

tracker = FlowTracker()
detector = Detector()
multiclass_detector = MulticlassDetector()
ensemble = EnsembleDetector(detector, scan_detector, multiclass_detector)
alert_manager = AlertManager()

import socket

def get_local_ip():
    """
    Gets the local IP address currently in use for outbound traffic,
    without hardcoding it. Works by opening a dummy UDP socket to a
    public IP (doesn't actually send data) and reading the local
    address the OS would use.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

def get_default_gateway():
    """
    Parses 'ipconfig' output to find the active adapter's default
    gateway IP, so we always scan/target something on the current
    network without hardcoding an IP.
    """
    try:
        output = subprocess.check_output("ipconfig", shell=True, text=True)
    except Exception:
        return None

    matches = re.findall(r"Default Gateway[.\s]*:\s*([\d.]+)", output)
    for match in matches:
        if match and match != "0.0.0.0":
            return match
    return None

def get_active_interface():
    """
    Returns the scapy interface currently used for the default route --
    avoids hardcoding 'Ethernet' vs a WiFi adapter name, which changes
    depending on which network/adapter is actually active.
    """
    return conf.iface

def process_packet(packet):
    if packet.haslayer(IP):
        proto_name = "OTHER"
        sport = dport = None
        header_length = packet[IP].ihl * 4  # IP header length in bytes
        tcp_flags = None

        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
            header_length += packet[TCP].dataofs * 4  # add TCP header length
            tcp_flags = str(packet[TCP].flags)  # e.g. "S", "SA", "PA", "FA"
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport

        info = {
            "timestamp": datetime.now().isoformat(),
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
            f"[{info['timestamp']}] {info['src']}:{info['sport']} -> "
            f"{info['dst']}:{info['dport']} | {info['protocol']} | {info['length']} bytes"
        )

        tracker.process_packet_info(info)  # feed into flow aggregation

        scan_alert = scan_detector.record_packet(
            src_ip=info["src"],
            dst_ip=info["dst"],
            dst_port=info["dport"],
        )
        if scan_alert:
            print(
                f"\n🚨 PORT SCAN DETECTED | {scan_alert['src_ip']} contacted "
                f"{scan_alert['distinct_ports_contacted']} distinct ports on "
                f"{scan_alert['target_ip']} within {scan_alert['window_seconds']}s\n"
            )
            alert_manager.recent_alerts.append(scan_alert)
            with open(alert_manager.log_file, "a") as f:
                f.write(json.dumps(scan_alert) + "\n")

        return info

def start_capture(interface=None, packet_count=0, bpf_filter=None, timeout=None):
    """
    interface: e.g. 'eth0' or 'Wi-Fi' (None = default)
    packet_count: 0 = capture indefinitely (ignored if timeout is set)
    bpf_filter: e.g. 'tcp or udp' to reduce noise
    timeout: if set, capture stops after this many seconds regardless of packet count
    """
    sniff(
        iface=interface,
        prn=process_packet,
        count=packet_count,
        filter=bpf_filter,
        timeout=timeout,
        store=False,  # don't keep packets in memory, important for long-running capture
    )



if __name__ == "__main__":
    import time

    local_ip = get_local_ip()
    print(f"Detected local IP: {local_ip}")

    active_iface = get_active_interface()
    print(f"Detected active interface: {active_iface}")

    target_ip = get_default_gateway()
    if not target_ip:
        print("Could not detect default gateway, falling back to manual entry.")
        target_ip = "192.168.5.1"
    print(f"Detected target IP (gateway): {target_ip}")

    run_scan_test(target_ip=target_ip)
    time.sleep(1)  # give nmap a moment to actually start sending packets

    start_capture(interface=active_iface, packet_count=0, bpf_filter=f"host {target_ip}", timeout=15)

    print("\nCapture stopped.")

    all_flows = tracker.get_active_flow_features() + tracker.get_completed_flows()

    print(f"\n--- {len(all_flows)} TOTAL FLOWS AFTER CAPTURE (ensemble decision) ---")
    for flow_features in all_flows:
        result = ensemble.evaluate(flow_features)
        signals = ", ".join(result["contributing_signals"]) if result["contributing_signals"] else "none"
        type_str = f" | type: {result['attack_type']}" if result["attack_type"] else ""
        print(f"{result['prediction']} (signals: {signals}) | "
              f"{result['src_ip']}:{result['src_port']} -> {result['dst_ip']}:{result['dst_port']} "
              f"[{result['protocol']}]{type_str}")
        alert_manager.process_detection(result)