"""
CipherShare Comprehensive Cryptographic Integration Test Suite
Tests:
1. User registration & persistent signing key generation (Alice, Bob, Eve).
2. Alice uploads a PDF/text file to Bob:
   - Verifies AES-256-CBC encryption.
   - Verifies SHA-256 digest of original plaintext.
   - Verifies persistent RSA-PSS digital signature over the SHA-256 digest.
   - Verifies HMAC-SHA256 generation.
   - Verifies granular performance timings recorded in DB.
3. Bob checks inbox:
   - File SHA-256 digest is displayed.
   - Digital signature is available and matches Alice's identity.
   - Cryptographic details card reflects correct parameters.
4. Bob downloads portable encrypted package (.cspkg):
   - Package is valid zip file containing payload.enc and metadata.json.
   - Metadata contains wrapped key, IV, HMAC, SHA-256, and RSA-PSS signature.
   - Metadata DOES NOT contain plaintext keys or private keys.
5. Bob verifies, decrypts, and downloads file (Option B):
   - Decrypted bytes match original byte-for-byte.
   - HMAC integrity is VALID.
   - SHA-256 matches original digest.
   - RSA-PSS digital signature is VALID.
6. Negative & Adversarial Security Checks:
   - Corrupt encrypted file payload -> HMAC rejection (INTEGRITY_CHECK_FAILED).
   - Tampered digital signature in DB -> Digital signature rejection.
   - Tampered SHA-256 digest in DB -> Hash mismatch rejection.
   - Eve (unauthorized user) attempts to download Bob's file -> Blocked (unauthorized).
   - Eve attempts to download Bob's package -> Blocked (unauthorized).
7. Legacy Compatibility:
   - File without signature or hash metadata remains downloadable via legacy workflow.
8. Performance dashboard API verification:
   - Actual file sharing performance metrics endpoint returns granular timings.
"""

import os
import sys
import io
import time
import json
import zipfile
import sqlite3

sys.path.insert(0, os.path.abspath("."))
from app import app
from database.models import get_db_connection

def run_integration_tests():
    print("============================================================")
    print(" CipherShare — Cryptographic File Sharing Integration Tests")
    print("============================================================")
    
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    c_alice = app.test_client()
    c_bob = app.test_client()
    c_eve = app.test_client()
    
    ts = int(time.time())
    alice_name = f"alice_{ts}"
    bob_name = f"bob_{ts}"
    eve_name = f"eve_{ts}"
    pwd = "SecurePassword123!"
    
    print("\n[STEP 1] Testing User Registration & Persistent Signing Keypair Provisioning...")
    for u, client in [(alice_name, c_alice), (bob_name, c_bob), (eve_name, c_eve)]:
        r = client.post('/register', data={'username': u, 'password': pwd, 'confirm_password': pwd}, follow_redirects=True)
        assert r.status_code == 200, f"Registration failed for {u}"
        
    db = get_db_connection()
    user_ids = {}
    for u in [alice_name, bob_name, eve_name]:
        row = db.execute('SELECT id, username, public_key, encrypted_private_key, signing_public_key, encrypted_signing_private_key FROM Users WHERE username = ?', (u,)).fetchone()
        assert row is not None, f"User {u} not found"
        assert row['public_key'] and "BEGIN PUBLIC KEY" in row['public_key'], f"Missing public_key for {u}"
        assert row['encrypted_private_key'], f"Missing encrypted_private_key for {u}"
        assert row['signing_public_key'] and "BEGIN PUBLIC KEY" in row['signing_public_key'], f"Missing signing_public_key for {u}"
        assert row['encrypted_signing_private_key'], f"Missing encrypted_signing_private_key for {u}"
        user_ids[u] = row['id']
        print(f"  [OK] User {u} (ID={row['id']}): Encryption & Dedicated Persistent Signing Keypairs Verified.")
    
    # Log in all users
    for u, client in [(alice_name, c_alice), (bob_name, c_bob), (eve_name, c_eve)]:
        r = client.post('/login', data={'username': u, 'password': pwd}, follow_redirects=True)
        assert r.status_code == 200
    print("  [OK] Alice, Bob, and Eve authenticated and sessions active.")

    print("\n[STEP 2] Testing File Upload with Automatic Hashing & Digital Signing (Alice -> Bob)...")
    # Create sample PDF-like / text payload
    original_content = (
        b"%PDF-1.4\n1 0 obj\n<< /Title (CipherShare Secure Integration Report) /Author (Alice) >>\n"
        b"stream\nConfidential research findings and end-to-end cryptographic proofs.\n"
        b"endstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )
    
    upload_resp = c_alice.post('/dashboard', data={
        'file': (io.BytesIO(original_content), 'research_report.pdf'),
        'receiver_id': str(user_ids[bob_name])
    }, content_type='multipart/form-data', follow_redirects=True)
    assert upload_resp.status_code == 200
    
    # Inspect database for File and DigitalSignature record
    file_row = db.execute('SELECT * FROM Files WHERE filename = ? ORDER BY id DESC LIMIT 1', ('research_report.pdf',)).fetchone()
    assert file_row is not None, "File record not found in database"
    file_id = file_row['id']
    file_hash = file_row['file_hash']
    sig_id = file_row['signature_id']
    
    print(f"  [OK] File #{file_id} created with encrypted_path: {file_row['encrypted_path']}")
    assert file_hash, "Original SHA-256 file_hash was not stored!"
    assert file_row['file_size_bytes'] == len(original_content), "Original file size mismatch!"
    assert sig_id, "signature_id was not linked in Files record!"
    
    # Verify digital signature record
    sig_row = db.execute('SELECT * FROM DigitalSignatures WHERE id = ?', (sig_id,)).fetchone()
    assert sig_row is not None, "Signature record not found"
    assert sig_row['user_id'] == user_ids[alice_name], "Signature does not belong to Alice!"
    assert sig_row['message'] == file_hash, "Signed message does not match file SHA-256 digest!"
    assert sig_row['signature'], "Signature Base64 is missing!"
    print(f"  [OK] Original File SHA-256: {file_hash}")
    print(f"  [OK] RSA-PSS Signature #{sig_id}: {sig_row['signature'][:32]}... (Sign Time: {sig_row['signing_time_ms']} ms)")
    
    # Verify PerformanceMetrics recorded granular timings
    perf_row = db.execute('SELECT * FROM PerformanceMetrics WHERE file_id = ? AND operation_type = "UPLOAD"', (file_id,)).fetchone()
    assert perf_row is not None, "Upload performance metrics not recorded!"
    assert perf_row['enc_time_ms'] is not None and perf_row['enc_time_ms'] > 0
    assert perf_row['key_wrap_time_ms'] is not None and perf_row['key_wrap_time_ms'] > 0
    assert perf_row['hmac_time_ms'] is not None and perf_row['hmac_time_ms'] > 0
    assert perf_row['hash_time_ms'] is not None and perf_row['hash_time_ms'] > 0
    assert perf_row['sig_time_ms'] is not None and perf_row['sig_time_ms'] > 0
    print(f"  [OK] Granular Upload Timings: AES={perf_row['enc_time_ms']:.2f}ms, Wrap={perf_row['key_wrap_time_ms']:.2f}ms, HMAC={perf_row['hmac_time_ms']:.2f}ms, SHA256={perf_row['hash_time_ms']:.2f}ms, Sign={perf_row['sig_time_ms']:.2f}ms")

    print("\n[STEP 3] Testing Bob's Inbox Display & Signature Verification API...")
    inbox_resp = c_bob.get('/inbox')
    assert inbox_resp.status_code == 200
    inbox_html = inbox_resp.get_data(as_text=True)
    assert 'research_report.pdf' in inbox_html
    assert file_hash in inbox_html, "File SHA-256 digest missing from inbox view"
    assert f"Signed by {alice_name}" in inbox_html, "Sender signature badge missing from inbox"
    
    # Call verify signature API as Bob
    ver_resp = c_bob.post('/api/file/verify-signature', json={'file_id': file_id})
    assert ver_resp.status_code == 200
    ver_data = ver_resp.get_json()
    assert ver_data['valid'] is True, f"Signature verification failed: {ver_data}"
    assert ver_data['sender_name'] == alice_name
    print(f"  [OK] Bob independently verified Alice's RSA-PSS signature: VALID in {ver_data['verification_time_ms']} ms.")

    print("\n[STEP 4] Testing OPTION A: Download Portable Encrypted Package (.cspkg)...")
    pkg_resp = c_bob.get(f'/download/package/{file_id}')
    assert pkg_resp.status_code == 200, f"Package download returned {pkg_resp.status_code}"
    assert pkg_resp.mimetype == "application/octet-stream"
    
    # Validate .cspkg ZIP archive structure
    with zipfile.ZipFile(io.BytesIO(pkg_resp.data), 'r') as zf:
        namelist = zf.namelist()
        assert 'metadata.json' in namelist, "metadata.json missing from .cspkg"
        assert 'payload.enc' in namelist, "payload.enc missing from .cspkg"
        
        meta = json.loads(zf.read('metadata.json').decode('utf-8'))
        assert meta['format'] == 'CipherShare-Package'
        assert meta['encryption']['cipher'] == 'AES-256-CBC'
        assert meta['file']['sha256_digest'] == file_hash
        assert meta['signature']['signature_b64'] == sig_row['signature']
        assert meta['signature']['signer_username'] == alice_name
        # Ensure security: No plaintext keys or private keys
        assert 'raw_aes_key' not in str(meta)
        assert 'plaintext' not in str(meta).lower()
        assert 'PRIVATE KEY' not in str(meta)
        
        payload_bytes = zf.read('payload.enc')
        assert original_content not in payload_bytes, "Security breach: Plaintext exposed in encrypted package payload!"
    print(f"  [OK] Valid portable package (.cspkg) downloaded: {len(pkg_resp.data)} bytes, genuine structure verified.")

    print("\n[STEP 5] Testing OPTION B: Verify, Decrypt and Download (Normal Valid Flow)...")
    dl_resp = c_bob.get(f'/download/{file_id}')
    assert dl_resp.status_code == 200, f"Decryption download returned {dl_resp.status_code}"
    assert dl_resp.data == original_content, "Decrypted content does NOT match original content byte-for-byte!"
    print(f"  [OK] Decrypted bytes match original byte-for-byte ({len(dl_resp.data)} bytes).")
    
    # Check download performance record
    dl_perf = db.execute('SELECT * FROM PerformanceMetrics WHERE file_id = ? AND operation_type = "DOWNLOAD"', (file_id,)).fetchone()
    assert dl_perf is not None
    assert dl_perf['status'] == 'SUCCESS'
    print(f"  [OK] Download Timings: KeyUnwrap={dl_perf['key_unwrap_time_ms']:.2f}ms, HMACVerify={dl_perf['hmac_verify_time_ms']:.2f}ms, AESDec={dl_perf['dec_time_ms']:.2f}ms, SHA256Verify={dl_perf['hash_verify_time_ms']:.2f}ms, SigVerify={dl_perf['sig_verify_time_ms']:.2f}ms")

    print("\n[STEP 6] Testing Negative & Adversarial Security Checks...")
    
    # 6A. Corrupt Encrypted Payload on Disk -> HMAC failure
    tamper_content = b"Content for HMAC Tamper Test"
    c_alice.post('/dashboard', data={'file': (io.BytesIO(tamper_content), 'tamper_hmac.txt'), 'receiver_id': str(user_ids[bob_name])}, content_type='multipart/form-data', follow_redirects=True)
    t_file = db.execute('SELECT * FROM Files WHERE filename = ? ORDER BY id DESC LIMIT 1', ('tamper_hmac.txt',)).fetchone()
    with open(t_file['encrypted_path'], 'r+b') as f:
        b = bytearray(f.read())
        b[-5] ^= 0xAA
        f.seek(0)
        f.write(b)
    
    t_dl = c_bob.get(f"/download/{t_file['id']}", follow_redirects=True)
    assert tamper_content not in t_dl.data, "Tampered ciphertext still yielded plaintext!"
    assert "integrity check failed" in t_dl.get_data(as_text=True).lower()
    print("  [OK] 6A. Payload Corruption correctly blocked by HMAC-SHA256 integrity check.")

    # 6B. Tampered Digital Signature in Database -> Signature verification failure
    c_alice.post('/dashboard', data={'file': (io.BytesIO(b"Data for sig tamper"), 'tamper_sig.txt'), 'receiver_id': str(user_ids[bob_name])}, content_type='multipart/form-data', follow_redirects=True)
    ts_file = db.execute('SELECT * FROM Files WHERE filename = ? ORDER BY id DESC LIMIT 1', ('tamper_sig.txt',)).fetchone()
    # Invert first character in stored signature
    cur = db.cursor()
    cur.execute("UPDATE DigitalSignatures SET signature = 'A' || SUBSTR(signature, 2) WHERE id = ?", (ts_file['signature_id'],))
    db.commit()
    
    ts_dl = c_bob.get(f"/download/{ts_file['id']}", follow_redirects=True)
    assert b"Data for sig tamper" not in ts_dl.data, "Tampered signature was accepted!"
    assert "signature verification failed" in ts_dl.get_data(as_text=True).lower()
    print("  [OK] 6B. Tampered digital signature correctly detected and download aborted.")

    # 6C. Tampered File Hash in Database -> Hash mismatch / signature failure
    c_alice.post('/dashboard', data={'file': (io.BytesIO(b"Data for hash tamper"), 'tamper_hash.txt'), 'receiver_id': str(user_ids[bob_name])}, content_type='multipart/form-data', follow_redirects=True)
    th_file = db.execute('SELECT * FROM Files WHERE filename = ? ORDER BY id DESC LIMIT 1', ('tamper_hash.txt',)).fetchone()
    cur.execute("UPDATE Files SET file_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE id = ?", (th_file['id'],))
    db.commit()
    
    th_dl = c_bob.get(f"/download/{th_file['id']}", follow_redirects=True)
    assert b"Data for hash tamper" not in th_dl.data, "Tampered SHA-256 hash was accepted!"
    assert "digest mismatch" in th_dl.get_data(as_text=True).lower()
    print("  [OK] 6C. Tampered SHA-256 digest correctly detected and download aborted.")

    # 6D. Unauthorized Access: Eve attempts to download Bob's file & package
    eve_dl = c_eve.get(f"/download/{file_id}", follow_redirects=True)
    assert original_content not in eve_dl.data
    assert "unauthorized" in eve_dl.get_data(as_text=True).lower()
    
    eve_pkg = c_eve.get(f"/download/package/{file_id}", follow_redirects=True)
    assert "unauthorized" in eve_pkg.get_data(as_text=True).lower()
    print("  [OK] 6D. Eve's unauthorized download attempts strictly blocked.")

    print("\n[STEP 7] Testing Legacy File Compatibility...")
    # Simulate a file created before the migration (no file_hash, no signature_id)
    from core.crypto import encrypt_file_data
    legacy_content = b"Legacy encrypted document before signature support."
    bob_rec = db.execute('SELECT public_key FROM Users WHERE id = ?', (user_ids[bob_name],)).fetchone()
    enc_data, enc_aes, iv, hmac = encrypt_file_data(legacy_content, bob_rec['public_key'])
    legacy_path = os.path.join(app.config['UPLOAD_FOLDER'], f"legacy_test_{ts}.enc")
    with open(legacy_path, 'wb') as f:
        f.write(enc_data)
        
    cur.execute(
        '''INSERT INTO Files (filename, sender_id, receiver_id, encrypted_path, encrypted_aes_key, iv, hmac_hash, file_hash, signature_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)''',
        ("legacy_doc.txt", user_ids[alice_name], user_ids[bob_name], legacy_path, enc_aes, iv, hmac)
    )
    legacy_id = cur.lastrowid
    db.commit()
    
    legacy_dl = c_bob.get(f"/download/{legacy_id}")
    assert legacy_dl.status_code == 200
    assert legacy_dl.data == legacy_content, "Legacy file decryption failed!"
    print(f"  [OK] Legacy file #{legacy_id} without signature successfully decrypted and downloaded.")

    print("\n[STEP 8] Testing Performance Dashboard Live File Sharing API...")
    perf_api_resp = c_bob.get('/api/performance/file-sharing')
    assert perf_api_resp.status_code == 200
    p_data = perf_api_resp.get_json()
    assert len(p_data) > 0, "No file sharing performance data returned!"
    first = p_data[0]
    assert 'enc_time_ms' in first or 'dec_time_ms' in first
    assert 'crypto_duration_ms' in first
    print(f"  [OK] /api/performance/file-sharing returned {len(p_data)} live records with full timing stages.")

    db.close()
    print("\n============================================================")
    print(" ALL 8 INTEGRATION PHASES PASSED WITH 100% SUCCESS!")
    print("============================================================")

if __name__ == '__main__':
    run_integration_tests()
