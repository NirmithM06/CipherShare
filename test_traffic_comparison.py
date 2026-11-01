"""
CipherShare - Phase 14 Traffic Analysis Comparison Test Suite
Tests repeatable scenario generation, cross-scenario metrics comparison,
CSV/JSON export, chart creation, heuristic verification, and privacy preservation.
"""

import os
import sys
import json
import csv
import tempfile
import pytest

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from traffic_analysis.comparator import (
    TrafficComparator,
    generate_scenario_pcaps
)
from traffic_analysis.analyzer import TrafficAnalyzer


@pytest.fixture
def temp_environment():
    """Create isolated temporary directories for captures and results."""
    captures_dir = tempfile.mkdtemp(prefix="captures_")
    results_dir = tempfile.mkdtemp(prefix="results_")
    yield captures_dir, results_dir

    # Cleanup
    for d in (captures_dir, results_dir):
        for root, dirs, files in os.walk(d, topdown=False):
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
            os.rmdir(d)
        except OSError:
            pass


def test_scenario_generation_repeatability(temp_environment):
    """Verify that generate_scenario_pcaps produces valid, reproducible PCAP fixtures."""
    captures_dir, _ = temp_environment
    scenarios = generate_scenario_pcaps(captures_dir=captures_dir)

    assert "Baseline_Ambient" in scenarios
    assert "CipherShare_Legitimate" in scenarios
    assert "Suspicious_Heuristic" in scenarios

    for name, meta in scenarios.items():
        filepath = meta["file"]
        assert os.path.exists(filepath)
        assert os.path.getsize(filepath) > 0
        assert "type" in meta
        assert "Synthetic" in meta["type"]


def test_traffic_comparison_execution(temp_environment):
    """Verify execution of comparison matrix across all three scenarios."""
    captures_dir, results_dir = temp_environment
    scenarios = generate_scenario_pcaps(captures_dir=captures_dir)

    comparator = TrafficComparator(scenarios=scenarios, server_port=5000, output_dir=results_dir)
    res = comparator.run_comparison()

    records = res["records"]
    assert len(records) == 3

    # Check Scenario 1 (Baseline)
    baseline = next(r for r in records if r["scenario_name"] == "Baseline_Ambient")
    assert baseline["ciphershare_traffic_detected"] is False
    assert baseline["ciphershare_port_packets"] == 0
    assert baseline["multi_port_probing_detected"] is False

    # Check Scenario 2 (Legitimate CipherShare)
    ciphershare = next(r for r in records if r["scenario_name"] == "CipherShare_Legitimate")
    assert ciphershare["ciphershare_traffic_detected"] is True
    assert ciphershare["ciphershare_port_packets"] > 0
    assert ciphershare["total_bytes"] > baseline["total_bytes"]

    # Check Scenario 3 (Suspicious Heuristics)
    suspicious = next(r for r in records if r["scenario_name"] == "Suspicious_Heuristic")
    assert suspicious["multi_port_probing_detected"] is True
    assert suspicious["syn_ratio_detected"] is True
    assert suspicious["total_heuristic_indicators"] >= 2


def test_comparison_artifacts_export(temp_environment):
    """Verify that export_comparison_artifacts generates all CSV, JSON, Markdown, and chart files."""
    captures_dir, results_dir = temp_environment
    scenarios = generate_scenario_pcaps(captures_dir=captures_dir)

    comparator = TrafficComparator(scenarios=scenarios, server_port=5000, output_dir=results_dir)
    comparator.run_comparison()
    artifacts = comparator.export_comparison_artifacts(generate_charts=True)

    assert "comparison_csv" in artifacts
    assert os.path.exists(artifacts["comparison_csv"])
    assert "comparison_json" in artifacts
    assert os.path.exists(artifacts["comparison_json"])
    assert "comparison_report_md" in artifacts
    assert os.path.exists(artifacts["comparison_report_md"])

    # Check CSV contents
    with open(artifacts["comparison_csv"], "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 3
        assert "scenario_name" in rows[0]
        assert "capture_type" in rows[0]
        assert "total_packets" in rows[0]
        assert "ciphershare_port_packets" in rows[0]

    # Check JSON contents
    with open(artifacts["comparison_json"], "r", encoding="utf-8") as f:
        data = json.load(f)
        assert "timestamp" in data
        assert "scenarios" in data
        assert len(data["scenarios"]) == 3

    # Check Markdown report contents
    with open(artifacts["comparison_report_md"], "r", encoding="utf-8") as f:
        md_text = f.read()
        assert "Baseline Ambient" in md_text
        assert "CipherShare Legitimate" in md_text
        assert "Suspicious" in md_text


def test_privacy_preservation_in_comparison(temp_environment):
    """Verify that comparison CSVs and JSONs contain no secrets, tokens, or encryption keys."""
    captures_dir, results_dir = temp_environment
    scenarios = generate_scenario_pcaps(captures_dir=captures_dir)

    comparator = TrafficComparator(scenarios=scenarios, server_port=5000, output_dir=results_dir)
    comparator.run_comparison()
    artifacts = comparator.export_comparison_artifacts(generate_charts=False)

    for key in ("comparison_csv", "comparison_json"):
        filepath = artifacts[key]
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().lower()
            assert "private_key" not in content
            assert "session_cookie" not in content
            assert "csrf_token" not in content
            assert "password_hash" not in content
            assert "aes_key" not in content


def test_empty_scenario_handling(temp_environment):
    """Verify that an empty scenarios dict is handled safely without crashing."""
    _, results_dir = temp_environment
    comparator = TrafficComparator(scenarios={}, server_port=5000, output_dir=results_dir)
    res = comparator.run_comparison()
    assert res["records"] == []
    assert res["summaries"] == {}

    artifacts = comparator.export_comparison_artifacts(generate_charts=True)
    assert os.path.exists(artifacts["comparison_report_md"])
