# Phase 13 — Network Traffic Analysis & Wireshark / PyShark Integration

## Overview
Phase 13 implements an offline and live-compatible network traffic analysis pipeline for **CipherShare**. It allows capturing or loading network packet dumps (`.pcap` / `.pcapng`), extracting packet metadata, computing traffic aggregations, identifying heuristic indicators (such as connection floods, SYN-heavy patterns, port scans, and CipherShare port activity), and exporting structured CSV/JSON summaries alongside visual Matplotlib charts.

---

## Architecture & Detection Engine
The traffic analyzer uses a dual-engine parser architecture:
1. **PyShark / TShark Engine**: Automatically detects system installations of `tshark` (Wireshark command-line backend) and PyShark.
2. **Native Fallback Engine (`dpkt`)**: When TShark is not installed or when running in restricted environments without administrator rights, the analyzer automatically falls back to an offline parser using `dpkt`. This allows seamless offline packet analysis on any platform without third-party binary prerequisites.

---

## Environment & Prerequisites

### Detected System Status
- **Python**: In project virtual environment (`.\venv\Scripts\python.exe`)
- **PyShark**: Available in `venv` (`pyshark==0.6`)
- **dpkt**: Available in `venv` (`dpkt==1.9.8`)
- **TShark / Wireshark**: Not installed by default on the host system.

### Installing Wireshark / TShark (Optional for Live Captures)
To enable live packet capture capabilities or full TShark decoding:
- **Windows (Winget)**:
  ```powershell
  winget install WiresharkFoundation.Wireshark
  ```
- **Windows (Chocolatey)**:
  ```powershell
  choco install wireshark
  ```
- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt update && sudo apt install -y tshark wireshark
  ```
- *Note:* Offline PCAP analysis works out of the box without installing Wireshark using the built-in parser.

---

## Features & Capabilities

### 1. Metadata Extraction
- **Timestamps**: Absolute and relative capture time (in seconds).
- **Addressing**: Source & Destination IPv4/IPv6 addresses, MAC addresses.
- **Transport Layer**: Protocol name (`TCP`, `UDP`, `ICMP`, etc.), source & destination ports.
- **TCP Control Flags**: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`.
- **Packet Metrics**: Frame length, payload lengths, and cumulative byte volume.

### 2. Statistical Aggregation
- Total packet count and byte throughput.
- Protocol distribution (packet counts and percentage breakdown).
- Packet size metrics: Minimum, Maximum, Mean, and Standard Deviation.
- Top communicating source and destination IP endpoints.
- Time-series traffic density (packets and bytes bucketed per second).

### 3. Transparent Heuristic Indicators
All heuristics are evaluated as transparent statistical indicators rather than definitive intrusion verdicts:
- **CipherShare Server Port Traffic**: Monitors traffic directed at or originating from the configured server port (`5000` by default).
- **High Request/Packet Rate**: Flags IP sources generating bursts exceeding configurable thresholds (`>100 pkts/sec`).
- **Multi-Port Scanning**: Detects single source IPs sending packets to multiple distinct destination ports (`>5 distinct ports`).
- **High TCP SYN Ratio**: Detects SYN-heavy connection attempts (`>40% SYN packets`).

### 4. Privacy & Safe Handling
- **No Payload Snooping**: The parser extracts only layer 2, 3, and 4 headers.
- **Zero Secret Exposure**: Passwords, session cookies, monitoring tokens, AES keys, RSA private keys, and uploaded file contents are never read, stored, or exported.
- **No Injection Vulnerabilities**: No user input or file paths are passed to external subshells.

---

## Output Artifacts
Analysis outputs are stored under `traffic_analysis/results/`:
1. `*_summary.json`: Detailed JSON summary including metadata, protocol breakdown, top endpoints, packet size statistics, and heuristic detections.
2. `*_packets.csv`: Sanitized packet-by-packet metadata table.
3. `*_protocols.csv`: Protocol breakdown and distribution metrics.
4. `*_protocols.png`: Matplotlib bar chart of protocol counts.
5. `*_packet_sizes.png`: Matplotlib histogram of packet length distribution.
6. `*_traffic_volume.png`: Matplotlib time-series plot of packet volume per second.

---

## Running Standalone Analysis
To generate a synthetic test capture and run the full analysis suite:

```powershell
.\venv\Scripts\python.exe traffic_analysis\analyzer.py
```

To analyze an existing capture file:
```python
from traffic_analysis.analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer("path/to/capture.pcap", ciphershare_port=5000)
summary = analyzer.analyze()
saved_files = analyzer.export_results(generate_charts=True)
print(f"Results written to: {saved_files}")
```

---

## Running Automated Tests
Run the dedicated Phase 13 test suite:
```powershell
.\venv\Scripts\python.exe -m pytest test_traffic_analysis.py -v
```

Run the complete regression suite:
```powershell
.\venv\Scripts\python.exe -m pytest test_script.py test_security_validation.py test_performance.py test_traffic_analysis.py -v
```
