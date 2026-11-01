"""
CipherShare Real-Time Performance & Traffic Data Collector & Graph Generator
Handles thread-safe persistence of upload/download metrics, application traffic events,
and automatic background debounced graph regeneration.
"""

import os
import sys
import time
import json
import sqlite3
import threading
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.models import get_db_connection
from core.time_utils import utc_now_str

PERF_RESULTS_DIR = os.path.join(BASE_DIR, 'performance', 'results')
TRAFFIC_RESULTS_DIR = os.path.join(BASE_DIR, 'traffic_analysis', 'results')

os.makedirs(PERF_RESULTS_DIR, exist_ok=True)
os.makedirs(TRAFFIC_RESULTS_DIR, exist_ok=True)


class LiveDataCollector:
    """
    Thread-safe collector for real-time performance and traffic metrics with debounced graph refresh.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._timer = None
        self._debounce_sec = 1.0  # Debounce graph generation to avoid thrashing during rapid requests

    def record_performance(self, operation_type: str, file_size_bytes: int, total_duration_ms: float,
                           crypto_duration_ms: float = None, status: str = "SUCCESS", details: str = None,
                           file_id: int = None, timings: dict = None):
        """
        Records an upload or download performance measurement into SQLite with granular timings.
        Guaranteed not to raise exceptions to the caller.
        """
        try:
            t = timings or {}
            current_utc = utc_now_str()
            db = get_db_connection()
            db.execute(
                """INSERT INTO PerformanceMetrics 
                   (timestamp, operation_type, file_size_bytes, crypto_duration_ms, total_duration_ms, status, details,
                    file_id, enc_time_ms, key_wrap_time_ms, hmac_time_ms, hash_time_ms, sig_time_ms,
                    dec_time_ms, key_unwrap_time_ms, hmac_verify_time_ms, hash_verify_time_ms, sig_verify_time_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    current_utc,
                    operation_type,
                    int(file_size_bytes),
                    float(crypto_duration_ms) if crypto_duration_ms is not None else None,
                    float(total_duration_ms),
                    status,
                    details,
                    file_id,
                    t.get('enc_time_ms'),
                    t.get('key_wrap_time_ms'),
                    t.get('hmac_time_ms'),
                    t.get('hash_time_ms'),
                    t.get('sig_time_ms'),
                    t.get('dec_time_ms'),
                    t.get('key_unwrap_time_ms'),
                    t.get('hmac_verify_time_ms'),
                    t.get('hash_verify_time_ms'),
                    t.get('sig_verify_time_ms')
                )
            )
            db.commit()
            db.close()
        except Exception as e:
            # Never let a metrics recording failure disrupt application workflows
            pass

        # Trigger automatic graph refresh
        self.schedule_graph_refresh()

    def record_traffic_event(self, ip_address: str, endpoint: str, method: str,
                             status_code: int, payload_size_bytes: int = 0,
                             event_category: str = "GENERAL", details: str = None):
        """
        Records an application-level traffic activity event into SQLite.
        Guaranteed not to raise exceptions to the caller.
        """
        try:
            current_utc = utc_now_str()
            db = get_db_connection()
            db.execute(
                """INSERT INTO TrafficActivity 
                   (timestamp, ip_address, endpoint, method, status_code, payload_size_bytes, event_category, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    current_utc,
                    ip_address,
                    endpoint,
                    method,
                    int(status_code),
                    int(payload_size_bytes),
                    event_category,
                    details
                )
            )
            db.commit()
            db.close()
        except Exception as e:
            pass

        # Trigger automatic graph refresh
        self.schedule_graph_refresh()

    def schedule_graph_refresh(self):
        """Schedules a debounced asynchronous graph refresh in a background daemon thread."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._debounce_sec, self._async_refresh)
            self._timer.daemon = True
            self._timer.start()

    def _async_refresh(self):
        try:
            self.refresh_all_graphs()
        except Exception:
            pass

    def refresh_all_graphs(self):
        """Generates all updated performance and traffic charts from persistent SQLite records."""
        try:
            self.generate_performance_graphs()
        except Exception:
            pass

        try:
            self.generate_traffic_graphs()
        except Exception:
            pass

    def generate_performance_graphs(self):
        """Generates performance charts from real recorded SQLite PerformanceMetrics data."""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
        except ImportError:
            return

        db = get_db_connection()
        rows = db.execute(
            """SELECT id, timestamp, operation_type, file_size_bytes, crypto_duration_ms, total_duration_ms, status 
               FROM PerformanceMetrics 
               ORDER BY id ASC"""
        ).fetchall()
        db.close()

        if not rows:
            # Handle empty state gracefully by creating placeholder info or empty charts
            self._generate_empty_chart(
                os.path.join(PERF_RESULTS_DIR, "live_performance_duration_over_time.png"),
                "Live Performance: Duration Over Time (No Data Recorded Yet)"
            )
            self._generate_empty_chart(
                os.path.join(PERF_RESULTS_DIR, "live_performance_filesize_vs_duration.png"),
                "Live Performance: File Size vs Duration (No Data Recorded Yet)"
            )
            self._generate_empty_chart(
                os.path.join(PERF_RESULTS_DIR, "live_performance_throughput.png"),
                "Live Performance: Throughput (No Data Recorded Yet)"
            )
            self._generate_empty_chart(
                os.path.join(PERF_RESULTS_DIR, "live_performance_crypto_overhead.png"),
                "Live Performance: Crypto Overhead (No Data Recorded Yet)"
            )
            return

        # Prepare data series
        upload_rows = [r for r in rows if r['operation_type'] == 'UPLOAD' and r['status'] == 'SUCCESS']
        download_rows = [r for r in rows if r['operation_type'] == 'DOWNLOAD' and r['status'] == 'SUCCESS']

        # Chart 1: Processing Duration Over Time (Sequence)
        plt.figure(figsize=(9, 4.8))
        if upload_rows:
            plt.plot(range(1, len(upload_rows) + 1), [r['total_duration_ms'] for r in upload_rows],
                     marker='o', color='#2980b9', label='Upload Duration (ms)', linewidth=2)
        if download_rows:
            plt.plot(range(1, len(download_rows) + 1), [r['total_duration_ms'] for r in download_rows],
                     marker='s', color='#27ae60', label='Download Duration (ms)', linewidth=2)
        plt.title('Live Application Activity: Processing Duration Over Events', fontsize=12, fontweight='bold')
        plt.xlabel('Event Sequence', fontweight='bold')
        plt.ylabel('Duration (ms)', fontweight='bold')
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(PERF_RESULTS_DIR, "live_performance_duration_over_time.png"), dpi=200)
        plt.close()

        # Chart 2: File Size vs Processing Duration
        plt.figure(figsize=(9, 4.8))
        if upload_rows:
            sizes_kb = [r['file_size_bytes'] / 1024.0 for r in upload_rows]
            plt.scatter(sizes_kb, [r['total_duration_ms'] for r in upload_rows],
                        color='#2980b9', alpha=0.8, s=60, label='Uploads', edgecolors='black')
        if download_rows:
            sizes_kb = [r['file_size_bytes'] / 1024.0 for r in download_rows]
            plt.scatter(sizes_kb, [r['total_duration_ms'] for r in download_rows],
                        color='#27ae60', alpha=0.8, s=60, label='Downloads', edgecolors='black')
        plt.title('Live Application Activity: File Size vs Processing Duration', fontsize=12, fontweight='bold')
        plt.xlabel('File Size (KB)', fontweight='bold')
        plt.ylabel('Duration (ms)', fontweight='bold')
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(PERF_RESULTS_DIR, "live_performance_filesize_vs_duration.png"), dpi=200)
        plt.close()

        # Chart 3: Measured Throughput (MB/s)
        plt.figure(figsize=(9, 4.8))
        all_success = [r for r in rows if r['status'] == 'SUCCESS' and r['total_duration_ms'] > 0]
        if all_success:
            throughputs = [
                ((r['file_size_bytes'] / (1024.0 * 1024.0)) / (r['total_duration_ms'] / 1000.0))
                for r in all_success
            ]
            plt.bar(range(1, len(throughputs) + 1), throughputs,
                    color='#8e44ad', edgecolor='black', alpha=0.85, width=0.5)
            plt.axhline(sum(throughputs) / len(throughputs), color='red', linestyle='--', label=f'Avg: {sum(throughputs)/len(throughputs):.2f} MB/s')
        plt.title('Live Application Activity: Measured Throughput (MB/s)', fontsize=12, fontweight='bold')
        plt.xlabel('Event Sequence', fontweight='bold')
        plt.ylabel('Throughput (MB/s)', fontweight='bold')
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(PERF_RESULTS_DIR, "live_performance_throughput.png"), dpi=200)
        plt.close()

        # Chart 4: Cryptographic Overhead vs Total Duration
        plt.figure(figsize=(9, 4.8))
        crypto_measured = [r for r in rows if r['crypto_duration_ms'] is not None and r['status'] == 'SUCCESS']
        if crypto_measured:
            idx = range(1, len(crypto_measured) + 1)
            total_d = [r['total_duration_ms'] for r in crypto_measured]
            crypto_d = [r['crypto_duration_ms'] for r in crypto_measured]
            plt.bar(idx, total_d, label='Total Processing Time (I/O + Overhead)', color='#bdc3c7', edgecolor='black', width=0.5)
            plt.bar(idx, crypto_d, label='Cryptographic Time (AES/RSA/HMAC)', color='#e74c3c', edgecolor='black', width=0.5)
            plt.legend()
        plt.title('Live Application Activity: Cryptographic Overhead vs Total Processing', fontsize=12, fontweight='bold')
        plt.xlabel('Event Sequence', fontweight='bold')
        plt.ylabel('Duration (ms)', fontweight='bold')
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.tight_layout()
        plt.savefig(os.path.join(PERF_RESULTS_DIR, "live_performance_crypto_overhead.png"), dpi=200)
        plt.close()

    def generate_traffic_graphs(self):
        """Generates application-level traffic activity graphs from real SQLite TrafficActivity data."""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
        except ImportError:
            return

        db = get_db_connection()
        rows = db.execute(
            """SELECT id, timestamp, ip_address, endpoint, method, status_code, payload_size_bytes, event_category 
               FROM TrafficActivity 
               ORDER BY id ASC"""
        ).fetchall()
        db.close()

        if not rows:
            self._generate_empty_chart(
                os.path.join(TRAFFIC_RESULTS_DIR, "live_traffic_activity_categories.png"),
                "Live Application Traffic: Event Categories (No Data Recorded Yet)"
            )
            self._generate_empty_chart(
                os.path.join(TRAFFIC_RESULTS_DIR, "live_traffic_volume_over_time.png"),
                "Live Application Traffic: Transfer Volume Over Time (No Data Recorded Yet)"
            )
            return

        # Chart 1: Application Event Categories Breakdown
        category_counts = defaultdict(int)
        for r in rows:
            category_counts[r['event_category']] += 1

        plt.figure(figsize=(8, 4.8))
        labels = list(category_counts.keys())
        counts = [category_counts[k] for k in labels]
        colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c'][:len(labels)]
        plt.bar(labels, counts, color=colors, edgecolor='black', alpha=0.85, width=0.5)
        plt.title('Live Application Traffic: Recorded Activity by Category', fontsize=12, fontweight='bold')
        plt.xlabel('Activity Category', fontweight='bold')
        plt.ylabel('Event Count', fontweight='bold')
        plt.grid(axis='y', linestyle=':', alpha=0.6)
        plt.tight_layout()
        plt.savefig(os.path.join(TRAFFIC_RESULTS_DIR, "live_traffic_activity_categories.png"), dpi=200)
        plt.close()

        # Chart 2: Cumulative Payload Transfer Volume Over Events
        plt.figure(figsize=(9, 4.8))
        cumulative_bytes = 0
        cum_volume = []
        for r in rows:
            cumulative_bytes += (r['payload_size_bytes'] or 0)
            cum_volume.append(cumulative_bytes / 1024.0)  # In KB

        plt.plot(range(1, len(cum_volume) + 1), cum_volume, color='#e67e22', marker='.', linewidth=2)
        plt.fill_between(range(1, len(cum_volume) + 1), cum_volume, color='#e67e22', alpha=0.2)
        plt.title('Live Application Traffic: Cumulative Transfer Volume (KB)', fontsize=12, fontweight='bold')
        plt.xlabel('Event Sequence', fontweight='bold')
        plt.ylabel('Cumulative Data (KB)', fontweight='bold')
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.tight_layout()
        plt.savefig(os.path.join(TRAFFIC_RESULTS_DIR, "live_traffic_volume_over_time.png"), dpi=200)
        plt.close()

    def _generate_empty_chart(self, filepath: str, title: str):
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            plt.figure(figsize=(8, 3.5))
            plt.text(0.5, 0.5, "No Activity Data Recorded Yet\n(Awaiting File Transfers or Application Activity)",
                     horizontalalignment='center', verticalalignment='center', fontsize=11, color='#7f8c8d')
            plt.title(title, fontsize=11, fontweight='bold')
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(filepath, dpi=150)
            plt.close()
        except Exception:
            pass


# Global singleton live collector
live_collector = LiveDataCollector()
