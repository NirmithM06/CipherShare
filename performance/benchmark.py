"""
CipherShare Performance Benchmarking Module (Phase 12)
Measures computational overhead, cryptographic execution times, and end-to-end local file transfer throughput.
"""

import os
import sys
import time
import csv
import io
import math
import struct
import platform
import statistics
from datetime import datetime
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC

# Add parent directory to path to allow importing app modules
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from database.models import get_db_connection, init_db
from core.crypto import generate_rsa_keypair, encrypt_file_data, decrypt_file_data
from core.security import security_manager

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')

# Supported benchmark file sizes (bytes)
BENCHMARK_SIZES = [
    (1 * 1024, "1_KB"),
    (100 * 1024, "100_KB"),
    (1 * 1024 * 1024, "1_MB"),
    (5 * 1024 * 1024, "5_MB"),
    (10 * 1024 * 1024, "10_MB"),
]


def generate_fixture_payload(size_bytes: int, file_type: str = "binary") -> bytes:
    """Generates deterministic test data for benchmarking without reading user files."""
    if file_type == "text":
        base_str = "CipherShare Performance Benchmark Deterministic Text Line 0123456789\n"
        repetitions = math.ceil(size_bytes / len(base_str))
        return (base_str * repetitions)[:size_bytes].encode('utf-8')
    elif file_type == "image":
        # Minimal valid PNG header + pseudo-image bytes
        png_hdr = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00'
        if size_bytes <= len(png_hdr):
            return (png_hdr * 2)[:size_bytes]
        fill = os.urandom(size_bytes - len(png_hdr))
        return png_hdr + fill
    else:
        # Pseudo-random reproducible binary payload
        return os.urandom(size_bytes)


def run_crypto_benchmarks(repeats: int = 5):
    """
    Measures granular cryptographic operation times across file sizes.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    raw_records = []
    summary_records = []

    print("=" * 70)
    print(" Running Granular Cryptographic Performance Benchmarks...")
    print(f" Repeats: {repeats} per size | Environment: Python {platform.python_version()} on {platform.system()}")
    print("=" * 70)

    # Pre-generate a test RSA key pair (2048-bit)
    pub_key_pem, priv_key_pem = generate_rsa_keypair("BenchPass123!")

    for size_bytes, size_label in BENCHMARK_SIZES:
        payload = generate_fixture_payload(size_bytes, "binary")
        print(f"\nEvaluating File Size: {size_label} ({size_bytes:,} bytes)")

        measurements = {
            'aes_encryption': [],
            'hmac_computation': [],
            'rsa_key_wrapping': [],
            'total_secure_encryption': [],
            'rsa_key_unwrapping': [],
            'hmac_verification': [],
            'aes_decryption': [],
            'total_secure_decryption': [],
            'plain_io_baseline_write': [],
            'plain_io_baseline_read': []
        }

        for rep in range(1, repeats + 1):
            # 1. Plain I/O baseline
            temp_path = os.path.join(RESULTS_DIR, f"temp_{size_label}.tmp")
            t0 = time.perf_counter()
            with open(temp_path, 'wb') as f:
                f.write(payload)
            t1 = time.perf_counter()
            io_write_ms = (t1 - t0) * 1000.0

            t0 = time.perf_counter()
            with open(temp_path, 'rb') as f:
                _ = f.read()
            t1 = time.perf_counter()
            io_read_ms = (t1 - t0) * 1000.0
            if os.path.exists(temp_path):
                os.remove(temp_path)

            measurements['plain_io_baseline_write'].append(io_write_ms)
            measurements['plain_io_baseline_read'].append(io_read_ms)

            # 2. Granular Encryption Steps
            # AES encryption alone
            aes_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            
            t0 = time.perf_counter()
            padded_data = pad(payload, AES.block_size)
            enc_data = cipher_aes.encrypt(padded_data)
            t1 = time.perf_counter()
            aes_enc_ms = (t1 - t0) * 1000.0
            measurements['aes_encryption'].append(aes_enc_ms)

            # HMAC computation alone
            hmac_key = HKDF(aes_key, 32, salt=b'', hashmod=SHA256, context=b'hmac_key_derivation')
            t0 = time.perf_counter()
            mac = HMAC.new(hmac_key, digestmod=SHA256)
            mac.update(iv)
            mac.update(enc_data)
            hmac_tag = mac.digest()
            t1 = time.perf_counter()
            hmac_comp_ms = (t1 - t0) * 1000.0
            measurements['hmac_computation'].append(hmac_comp_ms)

            # RSA key wrapping alone
            recipient_key = RSA.import_key(pub_key_pem)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            t0 = time.perf_counter()
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            t1 = time.perf_counter()
            rsa_wrap_ms = (t1 - t0) * 1000.0
            measurements['rsa_key_wrapping'].append(rsa_wrap_ms)

            # Total full pipeline encryption
            t0 = time.perf_counter()
            f_enc, f_k_b64, f_iv_b64, f_hmac_b64 = encrypt_file_data(payload, pub_key_pem)
            t1 = time.perf_counter()
            total_enc_ms = (t1 - t0) * 1000.0
            measurements['total_secure_encryption'].append(total_enc_ms)

            # 3. Granular Decryption Steps
            # RSA key unwrapping
            private_key = RSA.import_key(priv_key_pem, passphrase="BenchPass123!")
            cipher_rsa_dec = PKCS1_OAEP.new(private_key)
            t0 = time.perf_counter()
            decrypted_aes_key = cipher_rsa_dec.decrypt(encrypted_aes_key)
            t1 = time.perf_counter()
            rsa_unwrap_ms = (t1 - t0) * 1000.0
            measurements['rsa_key_unwrapping'].append(rsa_unwrap_ms)

            # HMAC verification alone
            mac_verify = HMAC.new(hmac_key, digestmod=SHA256)
            mac_verify.update(iv)
            mac_verify.update(enc_data)
            t0 = time.perf_counter()
            mac_verify.verify(hmac_tag)
            t1 = time.perf_counter()
            hmac_verify_ms = (t1 - t0) * 1000.0
            measurements['hmac_verification'].append(hmac_verify_ms)

            # AES decryption alone
            cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
            t0 = time.perf_counter()
            dec_data = unpad(cipher_aes_dec.decrypt(enc_data), AES.block_size)
            t1 = time.perf_counter()
            aes_dec_ms = (t1 - t0) * 1000.0
            measurements['aes_decryption'].append(aes_dec_ms)
            assert dec_data == payload

            # Total full pipeline decryption
            t0 = time.perf_counter()
            f_dec = decrypt_file_data(f_enc, f_k_b64, f_iv_b64, f_hmac_b64, priv_key_pem, "BenchPass123!")
            t1 = time.perf_counter()
            total_dec_ms = (t1 - t0) * 1000.0
            measurements['total_secure_decryption'].append(total_dec_ms)
            assert f_dec == payload

            # Record raw row
            for op_name, dur_val in [
                ('aes_encryption', aes_enc_ms),
                ('hmac_computation', hmac_comp_ms),
                ('rsa_key_wrapping', rsa_wrap_ms),
                ('total_secure_encryption', total_enc_ms),
                ('rsa_key_unwrapping', rsa_unwrap_ms),
                ('hmac_verification', hmac_verify_ms),
                ('aes_decryption', aes_dec_ms),
                ('total_secure_decryption', total_dec_ms),
                ('plain_io_baseline_write', io_write_ms),
                ('plain_io_baseline_read', io_read_ms),
            ]:
                thp_mb_s = (size_bytes / (1024 * 1024)) / (dur_val / 1000.0) if dur_val > 0 else 0
                raw_records.append({
                    'file_size_bytes': size_bytes,
                    'file_size_label': size_label,
                    'file_type': 'binary',
                    'operation': op_name,
                    'repetition': rep,
                    'duration_ms': round(dur_val, 4),
                    'throughput_mb_s': round(thp_mb_s, 2),
                    'python_version': platform.python_version(),
                    'os': platform.system(),
                    'timestamp': datetime.now().isoformat()
                })

        # Calculate Summary per size
        for op_name, dur_list in measurements.items():
            mean_dur = statistics.mean(dur_list)
            median_dur = statistics.median(dur_list)
            mean_thp = (size_bytes / (1024 * 1024)) / (mean_dur / 1000.0) if mean_dur > 0 else 0
            median_thp = (size_bytes / (1024 * 1024)) / (median_dur / 1000.0) if median_dur > 0 else 0

            summary_records.append({
                'file_size_bytes': size_bytes,
                'file_size_label': size_label,
                'operation': op_name,
                'repeats': repeats,
                'mean_duration_ms': round(mean_dur, 4),
                'median_duration_ms': round(median_dur, 4),
                'mean_throughput_mb_s': round(mean_thp, 2),
                'median_throughput_mb_s': round(median_thp, 2)
            })

        print(f" -> Total Encryption: Median = {statistics.median(measurements['total_secure_encryption']):.2f} ms")
        print(f" -> Total Decryption: Median = {statistics.median(measurements['total_secure_decryption']):.2f} ms")

    # Write Raw CSV
    raw_csv_path = os.path.join(RESULTS_DIR, 'crypto_benchmarks_raw.csv')
    with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=raw_records[0].keys())
        writer.writeheader()
        writer.writerows(raw_records)

    # Write Summary CSV
    summary_csv_path = os.path.join(RESULTS_DIR, 'crypto_benchmarks_summary.csv')
    with open(summary_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=summary_records[0].keys())
        writer.writeheader()
        writer.writerows(summary_records)

    print(f"\nCryptographic benchmark results saved to:")
    print(f" - {raw_csv_path}")
    print(f" - {summary_csv_path}")

    return raw_records, summary_records


def run_transfer_benchmarks(repeats: int = 5):
    """
    Measures end-to-end upload and download request duration and throughput through the Flask application.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    raw_records = []
    summary_records = []

    print("\n" + "=" * 70)
    print(" Running End-to-End Application Transfer Benchmarks...")
    print(" (Measures HTTP request handling, DB transactions, Encryption/Decryption, and File I/O)")
    print("=" * 70)

    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    security_manager.reset_all()

    with app.test_client() as client:
        # Create test users Alice and Bob
        client.post('/register', data={'username': 'bench_alice', 'password': 'AlicePassword123!'}, follow_redirects=True)
        client.post('/register', data={'username': 'bench_bob', 'password': 'BobPassword123!'}, follow_redirects=True)

        db = get_db_connection()
        bob_id = db.execute("SELECT id FROM Users WHERE username='bench_bob'").fetchone()['id']
        db.close()

        for size_bytes, size_label in BENCHMARK_SIZES:
            print(f"\nTransfer Benchmark: {size_label} ({size_bytes:,} bytes)")
            upload_durations = []
            download_durations = []
            e2e_durations = []

            for rep in range(1, repeats + 1):
                security_manager.reset_all()
                payload = generate_fixture_payload(size_bytes, "binary")
                fname = f"transfer_{size_label}_rep{rep}.bin"

                # 1. Login as Alice and Upload
                client.get('/logout', follow_redirects=True)
                client.post('/login', data={'username': 'bench_alice', 'password': 'AlicePassword123!'}, follow_redirects=False)

                upload_data = {
                    'receiver_id': str(bob_id),
                    'file': (io.BytesIO(payload), fname)
                }

                t0 = time.perf_counter()
                rv_up = client.post('/dashboard', data=upload_data, content_type='multipart/form-data', follow_redirects=False)
                t1 = time.perf_counter()
                upload_ms = (t1 - t0) * 1000.0
                assert rv_up.status_code == 302, f"Upload failed for {fname}"
                upload_durations.append(upload_ms)

                # Fetch File Record
                db = get_db_connection()
                rec = db.execute("SELECT id, encrypted_path FROM Files WHERE filename=? ORDER BY id DESC", (fname,)).fetchone()
                file_id = rec['id']
                enc_path = rec['encrypted_path']
                db.close()

                # 2. Login as Bob and Download
                client.get('/logout', follow_redirects=True)
                client.post('/login', data={'username': 'bench_bob', 'password': 'BobPassword123!'}, follow_redirects=False)

                t0 = time.perf_counter()
                rv_dl = client.get(f'/download/{file_id}', follow_redirects=False)
                t1 = time.perf_counter()
                download_ms = (t1 - t0) * 1000.0
                assert rv_dl.status_code == 200, f"Download failed for file {file_id}"
                assert rv_dl.data == payload, f"Downloaded data mismatch for {fname}"
                download_durations.append(download_ms)

                total_e2e_ms = upload_ms + download_ms
                e2e_durations.append(total_e2e_ms)

                # Calculate throughputs
                size_mb = size_bytes / (1024 * 1024)
                up_thp = size_mb / (upload_ms / 1000.0) if upload_ms > 0 else 0
                dl_thp = size_mb / (download_ms / 1000.0) if download_ms > 0 else 0
                e2e_thp = (size_mb * 2) / (total_e2e_ms / 1000.0) if total_e2e_ms > 0 else 0

                raw_records.append({
                    'file_size_bytes': size_bytes,
                    'file_size_label': size_label,
                    'operation': 'e2e_upload',
                    'repetition': rep,
                    'duration_ms': round(upload_ms, 4),
                    'throughput_mb_s': round(up_thp, 2),
                    'python_version': platform.python_version(),
                    'os': platform.system(),
                    'timestamp': datetime.now().isoformat()
                })
                raw_records.append({
                    'file_size_bytes': size_bytes,
                    'file_size_label': size_label,
                    'operation': 'e2e_download',
                    'repetition': rep,
                    'duration_ms': round(download_ms, 4),
                    'throughput_mb_s': round(dl_thp, 2),
                    'python_version': platform.python_version(),
                    'os': platform.system(),
                    'timestamp': datetime.now().isoformat()
                })
                raw_records.append({
                    'file_size_bytes': size_bytes,
                    'file_size_label': size_label,
                    'operation': 'total_e2e_roundtrip',
                    'repetition': rep,
                    'duration_ms': round(total_e2e_ms, 4),
                    'throughput_mb_s': round(e2e_thp, 2),
                    'python_version': platform.python_version(),
                    'os': platform.system(),
                    'timestamp': datetime.now().isoformat()
                })

                # Clean up stored encrypted file from disk
                if os.path.exists(enc_path):
                    try:
                        os.remove(enc_path)
                    except Exception:
                        pass

            # Summary per size
            for op_name, dur_list in [
                ('e2e_upload', upload_durations),
                ('e2e_download', download_durations),
                ('total_e2e_roundtrip', e2e_durations)
            ]:
                mean_dur = statistics.mean(dur_list)
                median_dur = statistics.median(dur_list)
                mult = 2 if op_name == 'total_e2e_roundtrip' else 1
                mean_thp = (size_mb * mult) / (mean_dur / 1000.0) if mean_dur > 0 else 0
                median_thp = (size_mb * mult) / (median_dur / 1000.0) if median_dur > 0 else 0

                summary_records.append({
                    'file_size_bytes': size_bytes,
                    'file_size_label': size_label,
                    'operation': op_name,
                    'repeats': repeats,
                    'mean_duration_ms': round(mean_dur, 4),
                    'median_duration_ms': round(median_dur, 4),
                    'mean_throughput_mb_s': round(mean_thp, 2),
                    'median_throughput_mb_s': round(median_thp, 2)
                })

            print(f" -> Upload Duration: Median = {statistics.median(upload_durations):.2f} ms ({size_mb / (statistics.median(upload_durations)/1000.0):.2f} MB/s)")
            print(f" -> Download Duration: Median = {statistics.median(download_durations):.2f} ms ({size_mb / (statistics.median(download_durations)/1000.0):.2f} MB/s)")

    raw_csv_path = os.path.join(RESULTS_DIR, 'transfer_benchmarks_raw.csv')
    with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=raw_records[0].keys())
        writer.writeheader()
        writer.writerows(raw_records)

    summary_csv_path = os.path.join(RESULTS_DIR, 'transfer_benchmarks_summary.csv')
    with open(summary_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=summary_records[0].keys())
        writer.writeheader()
        writer.writerows(summary_records)

    print(f"\nTransfer benchmark results saved to:")
    print(f" - {raw_csv_path}")
    print(f" - {summary_csv_path}")

    return raw_records, summary_records


def generate_benchmark_visualizations(crypto_summary, transfer_summary):
    """
    Generates Matplotlib performance charts based on collected benchmark data.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("Matplotlib not available. Visualizations skipped.")
        return

    print("\nGenerating performance visualization charts...")
    os.makedirs(RESULTS_DIR, exist_ok=True)

    sizes_kb = [row['file_size_bytes'] / 1024 for row in crypto_summary if row['operation'] == 'total_secure_encryption']
    size_labels = [row['file_size_label'] for row in crypto_summary if row['operation'] == 'total_secure_encryption']

    # 1. Plot: Encryption and Decryption Duration vs File Size
    plt.figure(figsize=(9, 5.5))
    enc_times = [row['median_duration_ms'] for row in crypto_summary if row['operation'] == 'total_secure_encryption']
    dec_times = [row['median_duration_ms'] for row in crypto_summary if row['operation'] == 'total_secure_decryption']
    aes_enc = [row['median_duration_ms'] for row in crypto_summary if row['operation'] == 'aes_encryption']
    aes_dec = [row['median_duration_ms'] for row in crypto_summary if row['operation'] == 'aes_decryption']

    plt.plot(size_labels, enc_times, marker='o', linewidth=2, color='#e74c3c', label='Total Secure Encrypt (AES+HMAC+RSA)')
    plt.plot(size_labels, dec_times, marker='s', linewidth=2, color='#3498db', label='Total Secure Decrypt (HMAC Verify+AES+RSA)')
    plt.plot(size_labels, aes_enc, marker='^', linestyle='--', color='#f39c12', label='AES-256-CBC Encrypt Alone')
    plt.plot(size_labels, aes_dec, marker='v', linestyle='--', color='#2ecc71', label='AES-256-CBC Decrypt Alone')

    plt.title('CipherShare: Cryptographic Processing Time vs. File Size', fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('File Size', fontsize=11)
    plt.ylabel('Median Processing Time (ms)', fontsize=11)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(frameon=True)
    plt.tight_layout()
    plot_crypto_path = os.path.join(RESULTS_DIR, 'crypto_processing_time.png')
    plt.savefig(plot_crypto_path, dpi=200)
    plt.close()
    print(f" -> Saved {plot_crypto_path}")

    # 2. Plot: HMAC Computation vs Verification Time
    plt.figure(figsize=(9, 5.5))
    hmac_comp = [row['median_duration_ms'] for row in crypto_summary if row['operation'] == 'hmac_computation']
    hmac_ver = [row['median_duration_ms'] for row in crypto_summary if row['operation'] == 'hmac_verification']

    plt.plot(size_labels, hmac_comp, marker='o', linewidth=2, color='#9b59b6', label='HMAC-SHA256 Generation')
    plt.plot(size_labels, hmac_ver, marker='D', linewidth=2, color='#1abc9c', label='HMAC-SHA256 Verification')

    plt.title('CipherShare: HMAC-SHA256 Integrity Processing Time vs. File Size', fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('File Size', fontsize=11)
    plt.ylabel('Median Time (ms)', fontsize=11)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(frameon=True)
    plt.tight_layout()
    plot_hmac_path = os.path.join(RESULTS_DIR, 'hmac_processing_time.png')
    plt.savefig(plot_hmac_path, dpi=200)
    plt.close()
    print(f" -> Saved {plot_hmac_path}")

    # 3. Plot: End-to-End Upload and Download Duration vs File Size
    plt.figure(figsize=(9, 5.5))
    up_times = [row['median_duration_ms'] for row in transfer_summary if row['operation'] == 'e2e_upload']
    dl_times = [row['median_duration_ms'] for row in transfer_summary if row['operation'] == 'e2e_download']

    plt.plot(size_labels, up_times, marker='o', linewidth=2, color='#d35400', label='E2E File Upload (Client -> Server -> Encrypt -> DB)')
    plt.plot(size_labels, dl_times, marker='s', linewidth=2, color='#2980b9', label='E2E File Download (Auth -> Verify -> Decrypt -> Client)')

    plt.title('CipherShare: End-to-End Application Transfer Duration vs. File Size', fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('File Size', fontsize=11)
    plt.ylabel('Median Duration (ms)', fontsize=11)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(frameon=True)
    plt.tight_layout()
    plot_transfer_path = os.path.join(RESULTS_DIR, 'transfer_duration.png')
    plt.savefig(plot_transfer_path, dpi=200)
    plt.close()
    print(f" -> Saved {plot_transfer_path}")

    # 4. Plot: Effective Throughput (MB/s) vs File Size
    plt.figure(figsize=(9, 5.5))
    up_thp = [row['median_throughput_mb_s'] for row in transfer_summary if row['operation'] == 'e2e_upload']
    dl_thp = [row['median_throughput_mb_s'] for row in transfer_summary if row['operation'] == 'e2e_download']
    crypto_enc_thp = [row['median_throughput_mb_s'] for row in crypto_summary if row['operation'] == 'total_secure_encryption']
    crypto_dec_thp = [row['median_throughput_mb_s'] for row in crypto_summary if row['operation'] == 'total_secure_decryption']

    plt.plot(size_labels, crypto_enc_thp, marker='^', linewidth=2, linestyle='--', color='#27ae60', label='Crypto Encryption Engine')
    plt.plot(size_labels, crypto_dec_thp, marker='v', linewidth=2, linestyle='--', color='#2ecc71', label='Crypto Decryption Engine')
    plt.plot(size_labels, up_thp, marker='o', linewidth=2, color='#e67e22', label='Application Upload Throughput')
    plt.plot(size_labels, dl_thp, marker='s', linewidth=2, color='#3498db', label='Application Download Throughput')

    plt.title('CipherShare: Effective Processing Throughput vs. File Size', fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('File Size', fontsize=11)
    plt.ylabel('Effective Throughput (MB/s)', fontsize=11)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(frameon=True)
    plt.tight_layout()
    plot_thp_path = os.path.join(RESULTS_DIR, 'throughput_vs_size.png')
    plt.savefig(plot_thp_path, dpi=200)
    plt.close()
    print(f" -> Saved {plot_thp_path}")


def main():
    print("=" * 70)
    print(" CipherShare Phase 12 - Performance & Overhead Benchmarking Suite")
    print("=" * 70)
    repeats = int(os.environ.get('BENCHMARK_REPEATS', 5))
    _, crypto_summary = run_crypto_benchmarks(repeats=repeats)
    _, transfer_summary = run_transfer_benchmarks(repeats=repeats)
    generate_benchmark_visualizations(crypto_summary, transfer_summary)
    print("\nPhase 12 Performance Benchmarks completed successfully.")


if __name__ == '__main__':
    main()
