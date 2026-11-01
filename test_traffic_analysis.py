"""
CipherShare - Phase 13 Network Traffic Analysis Test Suite
Tests offline PCAP parsing, protocol aggregation, heuristic detection,
error handling for malformed/empty files, output generation, and resource cleanup.
"""

import os
import sys
import pytest
import tempfile
import struct
import json
import csv

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from traffic_analysis.analyzer import (
    TrafficAnalyzer,
    generate_synthetic_pcap,
    detect_tshark_path
)


@pytest.fixture
def synthetic_pcap_path():
    """Generate a clean synthetic PCAP fixture containing normal and heuristic patterns."""
    temp_dir = tempfile.mkdtemp()
    pcap_file = os.path.join(temp_dir, "test_synthetic.pcap")
    generate_synthetic_pcap(pcap_file, num_packets=60)
    yield pcap_file
    # Cleanup
    if os.path.exists(pcap_file):
        try:
            os.remove(pcap_file)
        except OSError:
            pass
    if os.path.exists(temp_dir):
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass


@pytest.fixture
def temp_results_dir():
    """Create a temporary directory for output files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Cleanup all generated files in temp dir
    for root, dirs, files in os.walk(temp_dir, topdown=False):
        for name in files:
            try:
                os.remove(os.path.join(root, name))
            except OSError:
                pass
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                pass
    try:
        os.rmdir(temp_dir)
    except OSError:
        pass


def test_tshark_detection():
    """Verify that detect_tshark_path returns either a valid string path or None without raising exceptions."""
    tshark_path = detect_tshark_path()
    assert tshark_path is None or isinstance(tshark_path, str)
    if tshark_path:
        assert os.path.exists(tshark_path)


def test_synthetic_pcap_generation(synthetic_pcap_path):
    """Verify that synthetic PCAP generation produces a valid standard PCAP header and packets."""
    assert os.path.exists(synthetic_pcap_path)
    file_size = os.path.getsize(synthetic_pcap_path)
    assert file_size > 24  # Standard PCAP global header is 24 bytes

    with open(synthetic_pcap_path, "rb") as f:
        magic_bytes = f.read(4)
        # 0xa1b2c3d4 or 0xd4c3b2a1
        assert magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1")


def test_traffic_analyzer_parsing(synthetic_pcap_path, temp_results_dir):
    """Test full parsing and summary statistics computation."""
    analyzer = TrafficAnalyzer(synthetic_pcap_path, output_dir=temp_results_dir)
    summary = analyzer.analyze()

    assert summary["status"] == "success"
    assert summary["packet_count"] >= 50
    assert summary["total_bytes"] > 0
    assert "protocol_distribution" in summary
    assert "TCP" in summary["protocol_distribution"]
    assert "packet_size_stats" in summary
    assert summary["packet_size_stats"]["min"] > 0
    assert summary["packet_size_stats"]["max"] >= summary["packet_size_stats"]["min"]
    assert summary["packet_size_stats"]["avg"] > 0
    assert "top_sources" in summary
    assert "top_destinations" in summary


def test_heuristic_detection(synthetic_pcap_path, temp_results_dir):
    """Verify heuristic rule detection (SYN flags, CipherShare port, multi-port scans)."""
    analyzer = TrafficAnalyzer(synthetic_pcap_path, output_dir=temp_results_dir, ciphershare_port=5000)
    summary = analyzer.analyze()

    heuristics = summary.get("heuristic_indicators", {})
    assert "ciphershare_port_traffic" in heuristics
    assert "high_syn_ratio" in heuristics
    assert "multi_port_probing" in heuristics
    assert "high_rate_sources" in heuristics

    # The synthetic capture contains traffic to port 5000 and SYN packets
    cs_traffic = heuristics["ciphershare_port_traffic"]
    assert cs_traffic["detected"] is True
    assert cs_traffic["ciphershare_port"] == 5000
    assert cs_traffic["packet_count"] > 0


def test_output_generation(synthetic_pcap_path, temp_results_dir):
    """Verify that export_results creates JSON summary, packet CSV, protocol CSV, and graphs."""
    analyzer = TrafficAnalyzer(synthetic_pcap_path, output_dir=temp_results_dir)
    analyzer.analyze()
    saved_files = analyzer.export_results(generate_charts=True)

    # Check JSON output
    assert "summary_json" in saved_files
    json_path = saved_files["summary_json"]
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["packet_count"] > 0
        assert "heuristic_indicators" in data

    # Check Packet CSV output
    assert "packets_csv" in saved_files
    csv_path = saved_files["packets_csv"]
    assert os.path.exists(csv_path)
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) > 0
        assert "src_ip" in rows[0]
        assert "dst_ip" in rows[0]
        assert "protocol" in rows[0]
        assert "length" in rows[0]

    # Check Protocol CSV output
    assert "protocols_csv" in saved_files
    proto_csv_path = saved_files["protocols_csv"]
    assert os.path.exists(proto_csv_path)


def test_empty_pcap_handling(temp_results_dir):
    """Verify safe error handling when parsing an empty file."""
    empty_file = os.path.join(temp_results_dir, "empty.pcap")
    with open(empty_file, "wb") as f:
        pass  # 0 bytes

    analyzer = TrafficAnalyzer(empty_file, output_dir=temp_results_dir)
    with pytest.raises(ValueError, match="is empty"):
        analyzer.analyze()


def test_malformed_pcap_handling(temp_results_dir):
    """Verify safe error handling when parsing corrupt or non-PCAP bytes."""
    corrupt_file = os.path.join(temp_results_dir, "corrupt.pcap")
    with open(corrupt_file, "wb") as f:
        f.write(b"NOT_A_REAL_PCAP_HEADER_DATA_GARBAGE_1234567890")

    analyzer = TrafficAnalyzer(corrupt_file, output_dir=temp_results_dir)
    with pytest.raises(ValueError, match="Invalid or corrupt PCAP header"):
        analyzer.analyze()


def test_nonexistent_file_handling(temp_results_dir):
    """Verify FileNotFoundError on missing file."""
    missing_file = os.path.join(temp_results_dir, "does_not_exist.pcap")
    analyzer = TrafficAnalyzer(missing_file, output_dir=temp_results_dir)
    with pytest.raises(FileNotFoundError):
        analyzer.analyze()


def test_privacy_and_payload_exclusion(synthetic_pcap_path, temp_results_dir):
    """Verify that exported CSVs and JSONs contain only network metadata and never payload contents."""
    analyzer = TrafficAnalyzer(synthetic_pcap_path, output_dir=temp_results_dir)
    analyzer.analyze()
    saved = analyzer.export_results(generate_charts=False)

    with open(saved["packets_csv"], "r", encoding="utf-8") as f:
        content = f.read()
        # Verify sensitive field names or patterns are not stored
        assert "payload" not in content.lower()
        assert "secret" not in content.lower()
        assert "password" not in content.lower()
        assert "cookie" not in content.lower()
        assert "session" not in content.lower()
