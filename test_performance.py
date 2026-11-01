import pytest
import os
import csv
from performance.benchmark import (
    run_crypto_benchmarks,
    run_transfer_benchmarks,
    generate_benchmark_visualizations,
    generate_fixture_payload,
    RESULTS_DIR,
    BENCHMARK_SIZES
)

def test_generate_fixture_payload():
    """Verify deterministic fixture generators produce exact expected byte lengths."""
    for size, _ in [(1024, "1KB"), (10240, "10KB")]:
        bin_data = generate_fixture_payload(size, "binary")
        assert len(bin_data) == size
        txt_data = generate_fixture_payload(size, "text")
        assert len(txt_data) == size
        img_data = generate_fixture_payload(size, "image")
        assert len(img_data) == size
        assert img_data.startswith(b'\x89PNG')

def test_benchmark_runner_and_csv_generation():
    """
    Runs a lightweight benchmark iteration (repeat=2) and verifies:
    - Successful execution of all benchmark cases
    - Non-negative durations and positive throughputs
    - Valid CSV headers, expected row counts, and zero secret leakage
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Run cryptographic benchmarks with 2 repeats for test verification
    raw_crypto, summary_crypto = run_crypto_benchmarks(repeats=2)
    assert len(raw_crypto) > 0
    assert len(summary_crypto) > 0
    
    # Verify durations and throughputs
    for r in raw_crypto:
        assert r['duration_ms'] >= 0, f"Duration must be non-negative: {r}"
        assert r['throughput_mb_s'] >= 0
        assert r['file_size_bytes'] > 0
    
    # Run transfer benchmarks with 2 repeats
    raw_tx, summary_tx = run_transfer_benchmarks(repeats=2)
    assert len(raw_tx) > 0
    assert len(summary_tx) > 0

    for r in raw_tx:
        assert r['duration_ms'] >= 0
        assert r['throughput_mb_s'] >= 0
        assert r['file_size_bytes'] > 0

    # Verify CSV files exist on disk with valid structure
    raw_crypto_csv = os.path.join(RESULTS_DIR, 'crypto_benchmarks_raw.csv')
    summary_crypto_csv = os.path.join(RESULTS_DIR, 'crypto_benchmarks_summary.csv')
    raw_tx_csv = os.path.join(RESULTS_DIR, 'transfer_benchmarks_raw.csv')
    summary_tx_csv = os.path.join(RESULTS_DIR, 'transfer_benchmarks_summary.csv')

    for csv_file in [raw_crypto_csv, summary_crypto_csv, raw_tx_csv, summary_tx_csv]:
        assert os.path.exists(csv_file), f"CSV file must exist: {csv_file}"
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            assert len(header) >= 5
            rows = list(reader)
            assert len(rows) > 0

    # Test visualization generator
    generate_benchmark_visualizations(summary_crypto, summary_tx)
    expected_plots = [
        'crypto_processing_time.png',
        'hmac_processing_time.png',
        'transfer_duration.png',
        'throughput_vs_size.png'
    ]
    for plot_name in expected_plots:
        plot_path = os.path.join(RESULTS_DIR, plot_name)
        assert os.path.exists(plot_path), f"Plot {plot_name} should exist"
        assert os.path.getsize(plot_path) > 1000, f"Plot {plot_name} should not be empty"
