"""
CipherShare - Automated Data Collection & Live Graph Refresh Test Suite
Tests real-time performance logging, traffic activity recording, PNG generation,
persistence across server restart simulations, and failure isolation.
"""

import os
import sys
import io
import time
import json
import sqlite3
import tempfile
import pytest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app
from database.models import get_db_connection, init_db
from core.collector import live_collector, PERF_RESULTS_DIR, TRAFFIC_RESULTS_DIR


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


def test_upload_creates_performance_record_and_refreshes_png(client):
    """Verify that a real file upload creates a PerformanceMetrics entry and updates performance PNGs."""
    # Register Alice and Bob
    client.post('/register', data={'username': 'alice_live', 'password': 'Password123!'})
    client.post('/register', data={'username': 'bob_live', 'password': 'Password123!'})

    # Login as Alice
    client.post('/login', data={'username': 'alice_live', 'password': 'Password123!'})

    # Get Bob's ID
    db = get_db_connection()
    bob = db.execute("SELECT id FROM Users WHERE username = 'bob_live'").fetchone()
    db.close()

    # Upload test payload
    payload_content = b"Performance Measurement Live Payload Data " * 50
    data = {
        'receiver_id': bob['id'],
        'file': (io.BytesIO(payload_content), 'live_test.txt')
    }
    response = client.post('/dashboard', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200

    # Verify SQLite record created
    db = get_db_connection()
    perf_row = db.execute(
        "SELECT * FROM PerformanceMetrics WHERE operation_type = 'UPLOAD' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()

    assert perf_row is not None
    assert perf_row['file_size_bytes'] == len(payload_content)
    assert perf_row['total_duration_ms'] > 0
    assert perf_row['crypto_duration_ms'] is not None
    assert perf_row['status'] == 'SUCCESS'

    # Trigger and wait for graph refresh
    live_collector.refresh_all_graphs()

    # Check generated PNGs
    perf_png = os.path.join(PERF_RESULTS_DIR, "live_performance_duration_over_time.png")
    throughput_png = os.path.join(PERF_RESULTS_DIR, "live_performance_throughput.png")
    assert os.path.exists(perf_png)
    assert os.path.getsize(perf_png) > 0
    assert os.path.exists(throughput_png)
    assert os.path.getsize(throughput_png) > 0


def test_download_creates_performance_record_and_refreshes_png(client):
    """Verify that a real file download creates a PerformanceMetrics entry and updates performance PNGs."""
    # Login as Bob to download the file Alice sent
    client.post('/login', data={'username': 'bob_live', 'password': 'Password123!'})

    db = get_db_connection()
    file_record = db.execute("SELECT id, filename FROM Files ORDER BY id DESC LIMIT 1").fetchone()
    db.close()

    assert file_record is not None
    dl_response = client.get(f"/download/{file_record['id']}")
    assert dl_response.status_code == 200
    assert b"Performance Measurement Live Payload" in dl_response.data

    # Verify SQLite download record created
    db = get_db_connection()
    perf_row = db.execute(
        "SELECT * FROM PerformanceMetrics WHERE operation_type = 'DOWNLOAD' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()

    assert perf_row is not None
    assert perf_row['file_size_bytes'] > 0
    assert perf_row['total_duration_ms'] > 0
    assert perf_row['crypto_duration_ms'] is not None
    assert perf_row['status'] == 'SUCCESS'

    # Refresh graphs
    live_collector.refresh_all_graphs()

    crypto_png = os.path.join(PERF_RESULTS_DIR, "live_performance_crypto_overhead.png")
    assert os.path.exists(crypto_png)
    assert os.path.getsize(crypto_png) > 0


def test_traffic_activity_recording_and_png(client):
    """Verify application traffic events are recorded and traffic charts refreshed."""
    # Perform various actions
    client.get('/dashboard')
    client.get('/inbox')
    client.post('/login', data={'username': 'bob_live', 'password': 'WrongPassword!'})  # Failed login

    db = get_db_connection()
    traffic_rows = db.execute("SELECT * FROM TrafficActivity ORDER BY id DESC").fetchall()
    db.close()

    assert len(traffic_rows) > 0
    categories = [r['event_category'] for r in traffic_rows]
    assert 'AUTHENTICATION' in categories

    # Refresh traffic graphs
    live_collector.generate_traffic_graphs()

    traffic_cat_png = os.path.join(TRAFFIC_RESULTS_DIR, "live_traffic_activity_categories.png")
    traffic_vol_png = os.path.join(TRAFFIC_RESULTS_DIR, "live_traffic_volume_over_time.png")
    assert os.path.exists(traffic_cat_png)
    assert os.path.getsize(traffic_cat_png) > 0
    assert os.path.exists(traffic_vol_png)
    assert os.path.getsize(traffic_vol_png) > 0


def test_records_persist_across_restart_simulation():
    """Verify that performance and traffic records in SQLite persist across new app context / server restart."""
    db = get_db_connection()
    count_perf = db.execute("SELECT COUNT(*) as count FROM PerformanceMetrics").fetchone()['count']
    count_traffic = db.execute("SELECT COUNT(*) as count FROM TrafficActivity").fetchone()['count']
    db.close()

    assert count_perf > 0
    assert count_traffic > 0

    # Simulate fresh collector initialization
    fresh_collector = type(live_collector)()
    fresh_collector.refresh_all_graphs()

    # Ensure files still exist and are valid after re-generating from persistent DB
    perf_png = os.path.join(PERF_RESULTS_DIR, "live_performance_duration_over_time.png")
    assert os.path.exists(perf_png)
    assert os.path.getsize(perf_png) > 0


def test_graph_generation_failure_isolation(client, monkeypatch):
    """Verify that an unexpected error during graph generation does not break file uploads or downloads."""
    # Force an exception inside generate_performance_graphs
    def broken_graph_generator():
        raise RuntimeError("Simulated Matplotlib Crash")

    monkeypatch.setattr(live_collector, "generate_performance_graphs", broken_graph_generator)

    # Login as Alice and upload
    client.post('/login', data={'username': 'alice_live', 'password': 'Password123!'})
    db = get_db_connection()
    bob = db.execute("SELECT id FROM Users WHERE username = 'bob_live'").fetchone()
    db.close()

    data = {
        'receiver_id': bob['id'],
        'file': (io.BytesIO(b"Data during broken graph generation"), 'resilient.txt')
    }
    # Upload should succeed seamlessly
    response = client.post('/dashboard', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"File encrypted and sent successfully!" in response.data
