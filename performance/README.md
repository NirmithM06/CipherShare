# CipherShare Performance Benchmarking Guide (Phase 12)

This directory contains the performance analysis and benchmarking suite for **CipherShare: Secure Multi-Device File Sharing with Traffic Analysis and Intrusion Detection**.

---

## 1. Overview and Benchmark Scope

The benchmark suite measures:
1. **Granular Cryptographic Processing**:
   - `aes_encryption`: AES-256-CBC encryption of padded payload with randomized IV.
   - `hmac_computation`: HKDF key derivation + HMAC-SHA256 generation over `IV || ciphertext`.
   - `rsa_key_wrapping`: RSA-2048 PKCS#1 OAEP public key encryption of the ephemeral 32-byte AES key.
   - `total_secure_encryption`: Complete end-to-end sender encryption pipeline (`encrypt_file_data`).
   - `rsa_key_unwrapping`: Decryption of encrypted AES key with receiver's encrypted private key.
   - `hmac_verification`: HMAC-SHA256 tag verification (executed **prior** to decryption to fail safely on corrupted ciphertext).
   - `aes_decryption`: AES-256-CBC decryption and unpadding of verified ciphertext.
   - `total_secure_decryption`: Complete receiver decryption pipeline (`decrypt_file_data`).
   - `plain_io_baseline_write` / `plain_io_baseline_read`: Local disk read/write baseline without cryptographic overhead.

2. **End-to-End Application Transfer**:
   - `e2e_upload`: Time for an authenticated client to issue a `POST /dashboard` multipart request, stream data, encrypt on-the-fly, write ciphertext to disk, update the SQLite `Files` table, and write an audit log.
   - `e2e_download`: Time for an authenticated receiver to issue a `GET /download/<id>`, query SQLite, verify receiver authorization, verify HMAC-SHA256 integrity, decrypt ciphertext, and stream bytes to the client response.
   - `total_e2e_roundtrip`: Complete roundtrip upload + download processing cycle.
   - `throughput_mb_s`: Effective transfer speed in Megabytes per second ($MB/s$).

---

## 2. Test Fixtures and Supported File Sizes

Deterministic fixtures are synthesized locally across 5 standardized payload tiers:
- **1 KB** (1,024 bytes)
- **100 KB** (102,400 bytes)
- **1 MB** (1,048,576 bytes)
- **5 MB** (5,242,880 bytes)
- **10 MB** (10,485,760 bytes)

---

## 3. How to Run the Benchmark

### Running the Full Benchmark
From the project root:
```powershell
.\venv\Scripts\python.exe performance\benchmark.py
```

### Changing Repeat Counts and Parameters
The repeat count can be configured via the `BENCHMARK_REPEATS` environment variable:
```powershell
$env:BENCHMARK_REPEATS="10"
.\venv\Scripts\python.exe performance\benchmark.py
```

### Running Automated Performance Tests
```powershell
.\venv\Scripts\python.exe -m pytest test_performance.py -v
```

---

## 4. Understanding the Metrics

- **Mean vs. Median**:
  - `mean_duration_ms`: Arithmetic average across all repetitions.
  - `median_duration_ms`: 50th-percentile measurement, resilient against OS scheduling anomalies or background I/O spikes.
- **Cryptographic Engine vs. Application HTTP Overhead**:
  - The granular cryptographic engine operates directly in memory via high-resolution `time.perf_counter()`.
  - The application transfer benchmark measures full system latency, including Flask request parsing, multipart decoding, SQLite transactions, session management, and disk filesystem operations.
- **Throughput Calculation**:
  $$\text{Throughput (MB/s)} = \frac{\text{File Size (MB)}}{\text{Duration (seconds)}}$$

---

## 5. Generated Artifacts

All benchmark outputs are saved to `performance/results/`:
- **Raw Measurements**:
  - `crypto_benchmarks_raw.csv`
  - `transfer_benchmarks_raw.csv`
- **Statistical Summaries**:
  - `crypto_benchmarks_summary.csv`
  - `transfer_benchmarks_summary.csv`
- **Visualization Charts**:
  - `crypto_processing_time.png`: Cryptographic duration vs. file size.
  - `hmac_processing_time.png`: HMAC-SHA256 generation and verification vs. file size.
  - `transfer_duration.png`: E2E upload and download latency vs. file size.
  - `throughput_vs_size.png`: Effective throughput comparison across operations.

---

## 6. Limitations and Notes

1. **Local Test Harness vs. Physical Wi-Fi LAN**:
   - The benchmarks in this phase are conducted on a single local host using high-resolution timers and Flask's test client.
   - These measurements represent local CPU processing speed, I/O efficiency, and framework latency.
   - Physical wireless LAN network latency, Wi-Fi 802.11 packet contention, and multi-device radio throughput remain pending physical multi-device testing.
