"""
CipherShare Network Traffic Analysis Module (Phase 13)
Analyzes PCAP/PCAPNG network packet captures using PyShark (when TShark is installed)
with an integrated cross-platform fallback engine (dpkt) for offline capture parsing.
"""

import os
import sys
import json
import csv
import socket
import struct
import platform
import subprocess
from datetime import datetime
from collections import defaultdict, Counter

# Ensure parent directory is in path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import Config

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
CAPTURES_DIR = os.path.join(os.path.dirname(__file__), 'captures')


def detect_tshark_path():
    """Checks whether tshark executable is accessible in PATH or common directories."""
    # 1. Check system PATH
    try:
        proc = subprocess.run(["where", "tshark"], capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip().splitlines()[0]
    except Exception:
        pass

    # 2. Check standard Windows installations
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe")
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return p
    return None


class TrafficAnalyzer:
    """
    Offline PCAP and PCAPNG Traffic Analysis Engine for CipherShare.
    Supports single-capture analysis or reusable analysis instance.
    """
    def __init__(self, pcap_path: str = None, output_dir: str = None, server_port: int = None, ciphershare_port: int = None):
        self.pcap_path = pcap_path
        self.output_dir = output_dir or RESULTS_DIR
        # Support both server_port and ciphershare_port kwargs
        self.server_port = ciphershare_port if ciphershare_port is not None else (server_port if server_port is not None else 5000)
        self.tshark_path = detect_tshark_path()
        self.packets = []
        self.summary = {}
        self.parse_engine = "none"

    def analyze(self, pcap_path: str = None) -> dict:
        """
        Parses the PCAP file and computes the comprehensive analysis summary.
        """
        target_path = pcap_path or self.pcap_path
        if not target_path:
            raise ValueError("No PCAP path provided to analyze.")

        self.packets, self.parse_engine = self.parse_pcap(target_path)
        self.summary = self.analyze_traffic(self.packets)
        return self.summary

    def export_results(self, base_filename: str = "ciphershare_analysis", generate_charts: bool = True) -> dict:
        """Exports parsed packets and summary to JSON, CSV, and optional charts."""
        return self.save_analysis_results(
            packets=self.packets,
            summary=self.summary,
            base_filename=base_filename,
            output_dir=self.output_dir,
            generate_charts=generate_charts
        )

    def parse_pcap(self, pcap_path: str):
        """
        Parses a PCAP file and extracts packet-level metadata.
        Returns a tuple of (packet_records, parse_engine_name).
        """
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        file_size = os.path.getsize(pcap_path)
        if file_size == 0:
            raise ValueError("PCAP file is empty (0 bytes).")

        # Check PCAP header before parsing
        with open(pcap_path, 'rb') as f:
            magic = f.read(4)
            # Valid magic numbers for PCAP and PCAPNG
            valid_magics = (
                b'\xa1\xb2\xc3\xd4',  # standard microsecond PCAP
                b'\xd4\xc3\xb2\xa1',  # swapped microsecond PCAP
                b'\xa1\xb2\x3c\x4d',  # standard nanosecond PCAP
                b'\x4d\x3c\xb2\xa1',  # swapped nanosecond PCAP
                b'\x0a\x0d\x0d\x0a'   # PCAPNG Section Header Block
            )
            if magic not in valid_magics:
                raise ValueError(f"Invalid or corrupt PCAP header magic bytes: {magic.hex() if magic else 'empty'}")

        # Try PyShark if tshark is installed
        if self.tshark_path:
            try:
                import pyshark
                return self._parse_with_pyshark(pcap_path), "PyShark/TShark"
            except Exception:
                # Fallback to dpkt
                pass

        # Fallback native parsing via dpkt
        return self._parse_with_dpkt(pcap_path), "dpkt-native"

    def _parse_with_pyshark(self, pcap_path: str):
        import pyshark
        cap = pyshark.FileCapture(
            pcap_path,
            tshark_path=self.tshark_path,
            keep_packets=False
        )
        packets = []
        try:
            for idx, pkt in enumerate(cap, start=1):
                try:
                    ts = float(pkt.sniff_timestamp)
                except Exception:
                    ts = 0.0

                length = int(pkt.length) if hasattr(pkt, 'length') else 0
                highest_layer = pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'UNKNOWN'
                
                src_ip, dst_ip = 'UNKNOWN', 'UNKNOWN'
                src_port, dst_port = None, None
                transport = 'OTHER'
                tcp_flags = None

                if hasattr(pkt, 'ip'):
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                elif hasattr(pkt, 'ipv6'):
                    src_ip = pkt.ipv6.src
                    dst_ip = pkt.ipv6.dst

                if hasattr(pkt, 'tcp'):
                    transport = 'TCP'
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                    try:
                        raw_flags = int(pkt.tcp.flags, 16)
                        tcp_flags = {
                            'SYN': bool(raw_flags & 0x02),
                            'ACK': bool(raw_flags & 0x10),
                            'FIN': bool(raw_flags & 0x01),
                            'RST': bool(raw_flags & 0x04),
                            'PSH': bool(raw_flags & 0x08),
                            'URG': bool(raw_flags & 0x20)
                        }
                    except Exception:
                        tcp_flags = {}
                elif hasattr(pkt, 'udp'):
                    transport = 'UDP'
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                elif hasattr(pkt, 'icmp'):
                    transport = 'ICMP'

                packets.append({
                    'packet_number': idx,
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': transport,
                    'highest_layer': highest_layer,
                    'length': length,
                    'tcp_flags': tcp_flags
                })
        finally:
            cap.close()

        if not packets:
            raise ValueError("No valid packets could be decoded from capture file.")

        return packets

    def _parse_with_dpkt(self, pcap_path: str):
        import dpkt
        packets = []
        with open(pcap_path, 'rb') as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(f)
                except Exception as ex:
                    raise ValueError(f"Invalid or corrupt PCAP header: {ex}")

            idx = 1
            for ts, buf in reader:
                pkt_len = len(buf)
                src_ip, dst_ip = 'UNKNOWN', 'UNKNOWN'
                src_port, dst_port = None, None
                transport = 'OTHER'
                highest_layer = 'ETHERNET'
                tcp_flags = None

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    highest_layer = 'IPv4'

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        transport = 'TCP'
                        highest_layer = 'TCP'
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                        flags = ip.data.flags
                        tcp_flags = {
                            'SYN': bool(flags & dpkt.tcp.TH_SYN),
                            'ACK': bool(flags & dpkt.tcp.TH_ACK),
                            'FIN': bool(flags & dpkt.tcp.TH_FIN),
                            'RST': bool(flags & dpkt.tcp.TH_RST),
                            'PSH': bool(flags & dpkt.tcp.TH_PUSH),
                            'URG': bool(flags & dpkt.tcp.TH_URG)
                        }
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        transport = 'UDP'
                        highest_layer = 'UDP'
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        transport = 'ICMP'
                        highest_layer = 'ICMP'

                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip = eth.data
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
                    highest_layer = 'IPv6'

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        transport = 'TCP'
                        highest_layer = 'TCP'
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                        flags = ip.data.flags
                        tcp_flags = {
                            'SYN': bool(flags & dpkt.tcp.TH_SYN),
                            'ACK': bool(flags & dpkt.tcp.TH_ACK),
                            'FIN': bool(flags & dpkt.tcp.TH_FIN),
                            'RST': bool(flags & dpkt.tcp.TH_RST),
                            'PSH': bool(flags & dpkt.tcp.TH_PUSH),
                            'URG': bool(flags & dpkt.tcp.TH_URG)
                        }
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        transport = 'UDP'
                        highest_layer = 'UDP'
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        transport = 'ICMP'
                        highest_layer = 'ICMP'

                packets.append({
                    'packet_number': idx,
                    'timestamp': float(ts),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': transport,
                    'highest_layer': highest_layer,
                    'length': pkt_len,
                    'tcp_flags': tcp_flags
                })
                idx += 1

        if not packets:
            raise ValueError("No valid packets could be decoded from capture file.")

        return packets

    def analyze_traffic(self, packets: list) -> dict:
        """
        Computes traffic summaries, protocol distributions, and security heuristics.
        """
        if not packets:
            return {'status': 'success', 'packet_count': 0, 'total_packets': 0, 'total_bytes': 0}

        total_packets = len(packets)
        total_bytes = sum(p['length'] for p in packets)
        lengths = [p['length'] for p in packets]

        # Protocol counts
        protocol_counts = Counter(p['protocol'] for p in packets)
        layer_counts = Counter(p['highest_layer'] for p in packets)

        # Endpoints
        src_ip_counts = Counter(p['src_ip'] for p in packets if p['src_ip'] != 'UNKNOWN')
        dst_ip_counts = Counter(p['dst_ip'] for p in packets if p['dst_ip'] != 'UNKNOWN')

        # Temporal bounds
        timestamps = [p['timestamp'] for p in packets if p['timestamp'] > 0]
        start_ts = min(timestamps) if timestamps else 0
        end_ts = max(timestamps) if timestamps else 0
        duration_sec = max(0.001, end_ts - start_ts)

        # Heuristics & Indicators
        indicators = []
        heuristic_map = {
            "ciphershare_port_traffic": {"detected": False, "ciphershare_port": self.server_port, "packet_count": 0},
            "high_rate_sources": {"detected": False, "sources": []},
            "multi_port_probing": {"detected": False, "sources": []},
            "high_syn_ratio": {"detected": False, "sources": []}
        }

        # 1. Connections targeting CipherShare port
        ciphershare_traffic = [p for p in packets if p.get('dst_port') == self.server_port or p.get('src_port') == self.server_port]
        if ciphershare_traffic:
            cs_count = len(ciphershare_traffic)
            heuristic_map["ciphershare_port_traffic"] = {
                "detected": True,
                "ciphershare_port": self.server_port,
                "packet_count": cs_count
            }
            indicators.append({
                'category': 'APPLICATION_TRAFFIC',
                'severity': 'INFO',
                'description': f"Detected {cs_count} packets communicating on CipherShare server port {self.server_port}."
            })

        # 2. High packet rate per source IP
        rate_sources = []
        for ip, count in src_ip_counts.items():
            rate = count / duration_sec
            if count >= 20 and rate > 10.0:  # heuristic threshold
                rate_sources.append({"ip": ip, "rate": round(rate, 2), "count": count})
                indicators.append({
                    'category': 'TRAFFIC_BURST',
                    'severity': 'HEURISTIC_WARNING',
                    'description': f"Source IP {ip} generated high packet rate ({count} packets, ~{rate:.1f} pkt/s)."
                })
        if rate_sources:
            heuristic_map["high_rate_sources"] = {"detected": True, "sources": rate_sources}

        # 3. Port scan detection (single source probing multiple destination ports)
        src_dst_ports = defaultdict(set)
        for p in packets:
            if p.get('dst_port') is not None and p.get('src_ip') != 'UNKNOWN':
                src_dst_ports[p['src_ip']].add(p['dst_port'])

        port_scan_sources = []
        for ip, ports in src_dst_ports.items():
            if len(ports) >= 5:
                port_scan_sources.append({"ip": ip, "distinct_ports": len(ports)})
                indicators.append({
                    'category': 'RECONNAISSANCE_INDICATOR',
                    'severity': 'HEURISTIC_ALERT',
                    'description': f"Source IP {ip} probed {len(ports)} distinct destination ports. Potential port scan heuristic."
                })
        if port_scan_sources:
            heuristic_map["multi_port_probing"] = {"detected": True, "sources": port_scan_sources}

        # 4. High SYN ratio detection
        syn_counts = defaultdict(int)
        for p in packets:
            if p.get('tcp_flags') and p['tcp_flags'].get('SYN') and not p['tcp_flags'].get('ACK'):
                syn_counts[p['src_ip']] += 1

        syn_sources = []
        for ip, syn_cnt in syn_counts.items():
            total_for_ip = src_ip_counts.get(ip, 1)
            syn_ratio = (syn_cnt / total_for_ip) * 100
            if syn_cnt >= 10 and syn_ratio > 40:
                syn_sources.append({"ip": ip, "syn_count": syn_cnt, "ratio_pct": round(syn_ratio, 2)})
                indicators.append({
                    'category': 'CONNECTION_PATTERN',
                    'severity': 'HEURISTIC_WARNING',
                    'description': f"Source IP {ip} sent {syn_cnt} TCP SYN connection requests ({syn_ratio:.1f}% of its traffic)."
                })
        if syn_sources:
            heuristic_map["high_syn_ratio"] = {"detected": True, "sources": syn_sources}

        avg_size = round(total_bytes / total_packets, 2) if total_packets else 0
        min_size = min(lengths) if lengths else 0
        max_size = max(lengths) if lengths else 0

        summary = {
            'status': 'success',
            'capture_duration_seconds': round(duration_sec, 3),
            'packet_count': total_packets,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'packet_size_stats': {
                'min': min_size,
                'max': max_size,
                'avg': avg_size
            },
            'avg_packet_size_bytes': avg_size,
            'min_packet_size_bytes': min_size,
            'max_packet_size_bytes': max_size,
            'protocol_distribution': dict(protocol_counts),
            'protocols': dict(protocol_counts),
            'layers': dict(layer_counts),
            'top_sources': src_ip_counts.most_common(5),
            'top_destinations': dst_ip_counts.most_common(5),
            'top_source_ips': src_ip_counts.most_common(5),
            'top_destination_ips': dst_ip_counts.most_common(5),
            'indicators': indicators,
            'heuristic_indicators': heuristic_map
        }

        return summary

    def save_analysis_results(self, packets: list, summary: dict, base_filename: str = "capture_analysis", output_dir: str = None, generate_charts: bool = True):
        """Saves analysis results to JSON, CSV, and generated Matplotlib charts."""
        target_dir = output_dir or self.output_dir or RESULTS_DIR
        os.makedirs(target_dir, exist_ok=True)

        # 1. Save JSON Summary
        json_path = os.path.join(target_dir, f"{base_filename}_summary.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        # 2. Save Packet Metadata CSV
        packets_csv_path = os.path.join(target_dir, f"{base_filename}_packets.csv")
        if packets:
            with open(packets_csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=packets[0].keys())
                writer.writeheader()
                writer.writerows(packets)

        # 3. Save Protocol Distribution CSV
        proto_csv_path = os.path.join(target_dir, f"{base_filename}_protocols.csv")
        with open(proto_csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Protocol', 'Packet_Count', 'Percentage'])
            for proto, count in summary.get('protocols', {}).items():
                pct = (count / summary['total_packets']) * 100 if summary.get('total_packets') else 0
                writer.writerow([proto, count, f"{pct:.2f}%"])

        # 4. Generate Visualizations if Matplotlib is available and enabled
        if generate_charts:
            self._generate_plots(packets, summary, base_filename, target_dir)

        return {
            'summary_json': json_path,
            'json_summary': json_path,
            'packets_csv': packets_csv_path,
            'protocols_csv': proto_csv_path
        }

    def _generate_plots(self, packets: list, summary: dict, base_filename: str, target_dir: str = None):
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
        except ImportError:
            return

        if not packets:
            return

        save_dir = target_dir or self.output_dir or RESULTS_DIR

        # A. Protocol Distribution Pie Chart
        protocols = summary.get('protocols', {})
        if protocols:
            plt.figure(figsize=(7, 5))
            labels = list(protocols.keys())
            counts = list(protocols.values())
            colors = ['#3498db', '#2ecc71', '#e74c3c', '#9b59b6', '#f39c12'][:len(labels)]
            plt.pie(counts, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140)
            plt.title('CipherShare Network Capture: Protocol Distribution', fontsize=12, fontweight='bold')
            plt.tight_layout()
            plt.savefig(os.path.join(save_dir, f"{base_filename}_protocols.png"), dpi=200)
            plt.close()

        # B. Packet Size Distribution Histogram
        lengths = [p['length'] for p in packets]
        plt.figure(figsize=(8, 4.8))
        plt.hist(lengths, bins=20, color='#2980b9', edgecolor='black', alpha=0.8)
        plt.title('Packet Size Distribution (Bytes)', fontsize=12, fontweight='bold')
        plt.xlabel('Packet Length (Bytes)')
        plt.ylabel('Frequency')
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.tight_layout()
        plt.savefig(os.path.join(save_dir, f"{base_filename}_packet_sizes.png"), dpi=200)
        plt.close()

        # C. Traffic Volume Over Time
        timestamps = [p['timestamp'] for p in packets if p['timestamp'] > 0]
        if len(timestamps) > 1:
            min_t = min(timestamps)
            rel_times = [t - min_t for t in timestamps]
            plt.figure(figsize=(8.5, 4.8))
            plt.hist(rel_times, bins=25, color='#e67e22', edgecolor='black', alpha=0.8)
            plt.title('Captured Traffic Volume Over Time', fontsize=12, fontweight='bold')
            plt.xlabel('Relative Time (seconds)')
            plt.ylabel('Packets per Interval')
            plt.grid(True, linestyle=':', alpha=0.6)
            plt.tight_layout()
            plt.savefig(os.path.join(save_dir, f"{base_filename}_traffic_volume.png"), dpi=200)
            plt.close()


def generate_synthetic_pcap(filepath: str, num_packets: int = 25, simulate_scan: bool = False, server_port: int = 5000):
    """
    Generates a valid standard PCAP capture file for test execution without requiring live network interfaces.
    """
    import dpkt
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        pcap_writer = dpkt.pcap.Writer(f)
        base_time = 1700000000.0

        for i in range(num_packets):
            ts = base_time + (i * 0.05)
            # Create IP packet
            ip = dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.50" if not simulate_scan else "192.168.1.199"),
                dst=socket.inet_aton("192.168.1.10"),
                p=dpkt.ip.IP_PROTO_TCP,
                ttl=64
            )
            # Destination port
            dst_p = server_port if not simulate_scan else (1000 + i)
            tcp = dpkt.tcp.TCP(
                sport=54321 + i,
                dport=dst_p,
                flags=dpkt.tcp.TH_SYN if (i % 2 == 0 or simulate_scan) else dpkt.tcp.TH_ACK,
                seq=1000 + i,
                data=b"GET /dashboard HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n" if not simulate_scan else b""
            )
            ip.data = tcp
            ip.len = len(ip)

            # Wrap in Ethernet frame
            eth = dpkt.ethernet.Ethernet(
                src=b'\x00\x11\x22\x33\x44\x55',
                dst=b'\xaa\xbb\xcc\xdd\xee\xff',
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip
            )
            pcap_writer.writepkt(eth, ts)


def run_standalone_analysis(pcap_file: str = None):
    """Executes traffic analysis on a given PCAP file or generates a representative test capture."""
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    if not pcap_file:
        pcap_file = os.path.join(CAPTURES_DIR, "ciphershare_sample_traffic.pcap")
        print(f"Generating synthetic CipherShare traffic fixture at: {pcap_file}")
        generate_synthetic_pcap(pcap_file, num_packets=60, simulate_scan=False, server_port=5000)

    analyzer = TrafficAnalyzer(pcap_path=pcap_file, server_port=5000)
    print(f"Analyzing capture file: {pcap_file}")
    summary = analyzer.analyze()
    print(f" -> Parsed {summary['total_packets']} packets using engine: {analyzer.parse_engine}")

    out_files = analyzer.export_results(base_filename="ciphershare_analysis", generate_charts=True)

    print("\n--- Summary Results ---")
    print(f" Total Packets: {summary['total_packets']}")
    print(f" Total Bytes:   {summary['total_bytes']:,} bytes")
    print(f" Protocols:     {summary['protocols']}")
    print(f" Indicators:    {len(summary['indicators'])} heuristic observations")
    for ind in summary['indicators']:
        print(f"   [{ind['severity']}] {ind['description']}")

    print("\nOutputs saved to:")
    for k, v in out_files.items():
        print(f" - {k}: {v}")


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else None
    run_standalone_analysis(target)
