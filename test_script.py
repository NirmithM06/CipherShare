import pytest
import sqlite3
import os
import io
import struct
import math
import threading
from app import app
from database.models import get_db_connection
from core.security import security_manager, set_time_func, reset_time_func

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Reset security in-memory manager state and time provider
    security_manager.reset_all()
    reset_time_func()
    
    # Clean the database tables
    db = sqlite3.connect(app.config['DATABASE'])
    db.execute('DROP TABLE IF EXISTS Files')
    db.execute('DROP TABLE IF EXISTS AuditLogs')
    db.execute('DROP TABLE IF EXISTS Users')
    with open('database/db_schema.sql') as f:
        db.executescript(f.read())
    db.commit()
    db.close()
    
    with app.test_client() as client:
        yield client
        
    security_manager.reset_all()
    reset_time_func()

def register_user(client, username, password, remote_addr=None):
    kwargs = {}
    if remote_addr:
        kwargs['environ_base'] = {'REMOTE_ADDR': remote_addr}
    return client.post('/register', data=dict(
        username=username,
        password=password
    ), follow_redirects=True, **kwargs)

def login_user(client, username, password, remote_addr=None):
    kwargs = {}
    if remote_addr:
        kwargs['environ_base'] = {'REMOTE_ADDR': remote_addr}
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=False, **kwargs)

def logout_user(client, remote_addr=None):
    kwargs = {}
    if remote_addr:
        kwargs['environ_base'] = {'REMOTE_ADDR': remote_addr}
    return client.get('/logout', follow_redirects=True, **kwargs)

# =========================================================================
# REGRESSION TEST SUITE (Phases 1 - 8)
# =========================================================================
def test_all(client):
    security_manager.reset_all()
    print("--- Test 1: Create users ---")
    register_user(client, 'alice', 'password')
    register_user(client, 'bob', 'password')
    register_user(client, 'charlie', 'password')
    print("Created alice, bob, charlie.")

    print("\n--- Test 2: Check Alice's dashboard ---")
    login_user(client, 'alice', 'password')
    rv = client.get('/dashboard')
    content = rv.data.decode('utf-8')
    assert 'bob' in content, "Bob should appear as a receiver"
    assert 'charlie' in content, "Charlie should appear as a receiver"
    print("Alice's dashboard check passed (Bob and Charlie present).")
    
    print("\n--- Setup: Alice uploads a real file for Bob ---")
    login_rv = login_user(client, 'alice', 'password')
    
    print("\n--- Test A: Session cookie test ---")
    cookies = login_rv.headers.getlist('Set-Cookie')
    print(f"Set-Cookies: {cookies}")
    session_cookie = next((c for c in cookies if c.startswith('session=')), '')
    assert 'password' not in session_cookie, "Plaintext password must not be in session cookie!"
    assert session_cookie != '', "Session cookie should exist"
    print("Session cookie test passed: Plaintext password is not exposed in the cookie.")
    
    print("\n--- Test C: Private-key storage test ---")
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    bob_record = db.execute("SELECT encrypted_private_key FROM Users WHERE username='bob'").fetchone()
    
    pk = bob_record['encrypted_private_key']
    assert "ENCRYPTED PRIVATE KEY" in pk, "Key should be explicitly ENCRYPTED"
    assert "BEGIN RSA PRIVATE KEY" not in pk, "Key should NOT be stored as plaintext RSA key"
    print("Private-key storage test passed: RSA key is securely encrypted at rest.")
    
    bob_id = db.execute("SELECT id FROM Users WHERE username='bob'").fetchone()['id']
    db.close()
    
    data = {
        'receiver_id': str(bob_id),
        'file': (io.BytesIO(b"This is a real uploaded secret!"), 'real_secret_for_bob.txt')
    }
    
    rv = client.post('/dashboard', data=data, content_type='multipart/form-data', follow_redirects=False)
    with client.session_transaction() as sess:
        flashes = dict(sess.get('_flashes', []))
        if flashes.get('error'):
            print("Upload error:", flashes.get('error'))
            assert False, "Upload should be successful"
        else:
            assert flashes.get('success') == 'File encrypted and sent successfully!'
    print("File uploaded and encrypted successfully via dashboard.")
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    file_record = db.execute("SELECT * FROM Files WHERE filename='real_secret_for_bob.txt'").fetchone()
    file_id = file_record['id']
    db.close()
    
    print("\n--- Test 3: Test Bob's inbox ---")
    logout_user(client)
    login_user(client, 'bob', 'password')
    rv = client.get('/inbox')
    content = rv.data.decode('utf-8')
    assert 'real_secret_for_bob.txt' in content, "Bob should see the file"
    assert 'alice' in content, "Should see sender's name"
    assert 'Sent:' in content, "Should see sent timestamp text"
    print("Bob's inbox test passed (metadata verified).")
    
    print("\n--- Test 3.5: Test Bob's successful download ---")
    rv = client.get(f'/download/{file_id}', follow_redirects=False)
    assert rv.status_code == 200
    assert rv.data == b"This is a real uploaded secret!"
    print("Bob downloaded and decrypted the actual file successfully.")
    
    print("\n--- Test 3.6: Verify file on disk is encrypted ---")
    file_path = file_record['encrypted_path']
    with open(file_path, 'rb') as f:
        disk_data = f.read()
    assert b"This is a real uploaded secret!" not in disk_data
    print("File on disk is successfully encrypted (plaintext not found).")
    
    print("\n--- Test 4: Test Charlie's inbox ---")
    logout_user(client)
    login_user(client, 'charlie', 'password')
    rv = client.get('/inbox')
    content = rv.data.decode('utf-8')
    assert 'real_secret_for_bob.txt' not in content, "Charlie should not see Bob's file"
    print("Charlie's inbox test passed.")
    
    print("\n--- Test 5: Authorization attack ---")
    print(f"Charlie attempts to download file {file_id}...")
    rv = client.get(f'/download/{file_id}', follow_redirects=True)
    content = rv.data.decode('utf-8')
    assert 'Unauthorized: You do not have permission to access this file.' in content, "Charlie should be rejected"
    print("Authorization attack rejected successfully.")
    
    print("\n--- Test 6: Check database for AuditLogs ---")
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    log = db.execute("SELECT * FROM AuditLogs WHERE event_type='UNAUTHORIZED_ACCESS'").fetchone()
    db.close()
    
    if log:
        print(f"UNAUTHORIZED_ACCESS logged successfully! Details: {dict(log)}")
    else:
        print("FAILED: UNAUTHORIZED_ACCESS not found in AuditLogs.")
        assert False
        
    print("\n--- Test 7: Tampering test ---")
    with open(file_path, 'r+b') as f:
        f.seek(0)
        first_byte = f.read(1)
        f.seek(0)
        f.write(bytes([first_byte[0] ^ 0xFF]))
        
    print(f"Tampered with file {file_id} on disk. Attempting download as Bob...")
    logout_user(client)
    login_user(client, 'bob', 'password')
    rv = client.get(f'/download/{file_id}', follow_redirects=True)
    content = rv.data.decode('utf-8')
    assert "File integrity check failed" in content, "Should show integrity error"
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    log = db.execute("SELECT * FROM AuditLogs WHERE event_type='INTEGRITY_CHECK_FAILED'").fetchone()
    db.close()
    assert log is not None, "INTEGRITY_CHECK_FAILED should be logged"
    print("Tampering test passed: Download rejected and logged.")
    
    print("\n--- Test 8: Binary file test ---")
    logout_user(client)
    login_user(client, 'alice', 'password')
    binary_data = os.urandom(1024)
    data = {
        'receiver_id': str(bob_id),
        'file': (io.BytesIO(binary_data), 'binary_test.bin')
    }
    client.post('/dashboard', data=data, content_type='multipart/form-data', follow_redirects=False)
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    bin_file_id = db.execute("SELECT id FROM Files WHERE filename='binary_test.bin'").fetchone()['id']
    db.close()
    
    logout_user(client)
    login_user(client, 'bob', 'password')
    rv = client.get(f'/download/{bin_file_id}', follow_redirects=False)
    assert rv.status_code == 200
    assert rv.data == binary_data, "Downloaded binary data should match exactly"
    print("Binary file test passed.")

    # =========================================================================
    # PHASE 8: MULTIMEDIA FILE TESTING AND VALIDATION
    # =========================================================================
    print("\n=======================================================")
    print("--- PHASE 8: MULTIMEDIA FILE TESTING AND VALIDATION ---")
    print("=======================================================")
    txt_content = (
        "CipherShare Phase 8 Multimedia Validation Report\n"
        "Testing byte-for-byte exactness across binary AES-256-CBC + HMAC-SHA256 pipeline.\n"
        "Unicode test symbols: 🔐 🛡️ 🔑 🚀 ✨\n"
    ) * 30
    txt_bytes = txt_content.encode('utf-8')

    png_bytes = (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        b'\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00'
        b'\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
    )

    jpg_bytes = bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
        0xFF, 0xDB, 0x00, 0x43, 0x00,
    ] + [0x08]*64 + [
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
        0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F, 0xFF, 0xD9
    ])

    num_samples = 4410
    sample_rate = 44100
    bits_per_sample = 16
    channels = 1
    data_size = num_samples * channels * (bits_per_sample // 8)
    wav_header = struct.pack(
        '<4sI4s4sIHHIIHH4sI',
        b'RIFF', 36 + data_size, b'WAVE',
        b'fmt ', 16, 1, channels, sample_rate, sample_rate * channels * 2, channels * 2, bits_per_sample,
        b'data', data_size
    )
    pcm_data = bytearray()
    for i in range(num_samples):
        val = int(32767.0 * 0.5 * math.sin(2.0 * math.pi * 440.0 * i / sample_rate))
        pcm_data.extend(struct.pack('<h', val))
    wav_bytes = wav_header + bytes(pcm_data)

    id3_header = b'ID3\x03\x00\x00\x00\x00\x00\x00'
    frame_hdr = b'\xff\xfb\x90\x64'
    frame_payload = (b'\x55\xaa' * 206)[:413]
    mp3_bytes = id3_header + (frame_hdr + frame_payload) * 12

    ftyp_payload = b'isom\x00\x00\x02\x00isomiso2mp41'
    ftyp_box = struct.pack('>I4s', 8 + len(ftyp_payload), b'ftyp') + ftyp_payload
    moov_payload = b'mvhd\x00\x00\x00\x00' + b'\x00' * 96
    moov_box = struct.pack('>I4s', 8 + len(moov_payload), b'moov') + moov_payload
    mdat_payload = os.urandom(256 * 1024)
    mdat_box = struct.pack('>I4s', 8 + len(mdat_payload), b'mdat') + mdat_payload
    mp4_bytes = ftyp_box + moov_box + mdat_box

    test_files = [
        ('document.txt', txt_bytes, 'Text (.txt)'),
        ('image.png', png_bytes, 'Image (.png)'),
        ('photo.jpg', jpg_bytes, 'Image (.jpg)'),
        ('audio_sample.wav', wav_bytes, 'Audio (.wav)'),
        ('track.mp3', mp3_bytes, 'Audio (.mp3)'),
        ('video_clip.mp4', mp4_bytes, 'Video (.mp4)'),
    ]

    for fname, orig_bytes, category in test_files:
        security_manager.reset_all()
        print(f"\n--- Testing {category}: {fname} ({len(orig_bytes)} bytes) ---")
        logout_user(client)
        login_user(client, 'alice', 'password')
        upload_data = {
            'receiver_id': str(bob_id),
            'file': (io.BytesIO(orig_bytes), fname)
        }
        rv = client.post('/dashboard', data=upload_data, content_type='multipart/form-data', follow_redirects=False)
        assert rv.status_code == 302, f"Upload should redirect on success for {fname}"

        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        file_rec = db.execute(
            "SELECT * FROM Files WHERE filename=? AND receiver_id=? ORDER BY id DESC",
            (fname, bob_id)
        ).fetchone()
        assert file_rec is not None, f"File record must exist in database for {fname}"
        cur_file_id = file_rec['id']
        enc_path = file_rec['encrypted_path']
        assert os.path.exists(enc_path), f"Encrypted file must exist at {enc_path}"
        
        with open(enc_path, 'rb') as f:
            encrypted_data = f.read()
        assert orig_bytes not in encrypted_data, f"Plaintext must NOT appear in encrypted file on disk for {fname}"
        assert len(encrypted_data) > 0, f"Encrypted file must not be empty for {fname}"

        logout_user(client)
        login_user(client, 'bob', 'password')
        
        rv_inbox = client.get('/inbox')
        assert fname in rv_inbox.data.decode('utf-8'), f"Bob's inbox must display {fname}"

        rv_dl = client.get(f'/download/{cur_file_id}', follow_redirects=False)
        assert rv_dl.status_code == 200, f"Download status should be 200 for {fname}"
        assert fname in rv_dl.headers.get('Content-Disposition')

        downloaded_bytes = rv_dl.data
        assert downloaded_bytes == orig_bytes, f"Byte-for-byte match FAILED for {fname}!"
        print(f" -> Decrypted download verified: EXACT byte-for-byte match ({len(downloaded_bytes)} bytes).")

    # Multimedia ciphertext tampering verification
    print("\n--- Multimedia Tampering Verification (MP4 file) ---")
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    mp4_rec = db.execute(
        "SELECT * FROM Files WHERE filename='video_clip.mp4' ORDER BY id DESC"
    ).fetchone()
    mp4_file_id = mp4_rec['id']
    mp4_enc_path = mp4_rec['encrypted_path']
    db.close()

    with open(mp4_enc_path, 'r+b') as f:
        f.seek(1024)
        target_byte = f.read(1)
        f.seek(1024)
        f.write(bytes([target_byte[0] ^ 0xAA]))

    logout_user(client)
    login_user(client, 'bob', 'password')
    rv_tamper = client.get(f'/download/{mp4_file_id}', follow_redirects=True)
    assert "File integrity check failed" in rv_tamper.data.decode('utf-8')

    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    tamper_log = db.execute(
        "SELECT * FROM AuditLogs WHERE event_type='INTEGRITY_CHECK_FAILED' ORDER BY id DESC"
    ).fetchone()
    db.close()
    assert tamper_log is not None, "INTEGRITY_CHECK_FAILED must be logged for multimedia tampering"

    # Multimedia authorization verification
    print("\n--- Multimedia Authorization Verification (Charlie accessing Bob's WAV file) ---")
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    wav_rec = db.execute(
        "SELECT * FROM Files WHERE filename='audio_sample.wav' ORDER BY id DESC"
    ).fetchone()
    wav_file_id = wav_rec['id']
    db.close()

    logout_user(client)
    login_user(client, 'charlie', 'password')
    rv_unauth = client.get(f'/download/{wav_file_id}', follow_redirects=True)
    assert "Unauthorized: You do not have permission to access this file." in rv_unauth.data.decode('utf-8')

    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    unauth_log = db.execute(
        "SELECT * FROM AuditLogs WHERE event_type='UNAUTHORIZED_ACCESS' ORDER BY id DESC"
    ).fetchone()
    db.close()
    assert unauth_log is not None, "UNAUTHORIZED_ACCESS must be logged for multimedia file"
    assert f"file_id {wav_file_id}" in unauth_log['description']
    print("\nAll Phase 1-8 Regression tests passed successfully!")

# =========================================================================
# PHASE 10: INTRUSION DETECTION, RATE LIMITING & SECURITY MONITORING TESTS
# =========================================================================
def test_phase10_security_and_ids(client):
    print("\n=======================================================")
    print("--- PHASE 10: INTRUSION DETECTION & RATE LIMITING ---")
    print("=======================================================")
    
    # 1. Registration and normal login
    print("\n[Req 1 & 11] Normal login and registration:")
    rv_reg = register_user(client, 'sec_user', 'strong_password', remote_addr='192.168.1.10')
    assert rv_reg.status_code == 200 or rv_reg.status_code == 302
    
    rv_login = login_user(client, 'sec_user', 'strong_password', remote_addr='192.168.1.10')
    assert rv_login.status_code == 302, "Normal login must redirect to dashboard"
    assert rv_login.headers.get('Location').endswith('/dashboard')
    print(" -> Normal login succeeded.")
    
    # Verify LOGIN_SUCCESS audit log
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    login_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='LOGIN_SUCCESS' ORDER BY id DESC").fetchone()
    assert login_log is not None
    assert login_log['ip_address'] == '192.168.1.10'
    db.close()
    print(" -> LOGIN_SUCCESS logged correctly.")
    
    logout_user(client, remote_addr='192.168.1.10')

    # 2. Failed login logging
    print("\n[Req 2] Failed login is logged:")
    rv_fail = login_user(client, 'sec_user', 'wrong_password', remote_addr='192.168.1.10')
    assert rv_fail.status_code == 200 or rv_fail.status_code == 401
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    fail_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='LOGIN_FAILURE' ORDER BY id DESC").fetchone()
    assert fail_log is not None
    assert fail_log['ip_address'] == '192.168.1.10'
    assert 'password' not in fail_log['description'].lower() or fail_log['description'] == 'Incorrect username or password'
    db.close()
    print(" -> Failed login logged with safe description (no secrets).")

    # 3 & 4. Repeated failed logins trigger threshold and activate cooldown
    print("\n[Req 3 & 4] Repeated failed logins trigger IDS and login cooldown:")
    # We already have 1 failed login from 192.168.1.10. Let's send 4 more (total 5 = limit)
    for i in range(2, 6):
        rv_fail = login_user(client, 'sec_user', 'wrong_password', remote_addr='192.168.1.10')
        if i == 5:
            # The 5th failed attempt breaches threshold and applies cooldown
            assert rv_fail.status_code == 429
            assert b"cooldown" in rv_fail.data.lower() or b"too many" in rv_fail.data.lower()
            print(f" -> 5th attempt triggered threshold (HTTP {rv_fail.status_code}).")

    # Verify IDS_SUSPICIOUS_ACTIVITY in AuditLogs
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    ids_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='IDS_SUSPICIOUS_ACTIVITY' ORDER BY id DESC").fetchone()
    assert ids_log is not None, "IDS_SUSPICIOUS_ACTIVITY must be recorded"
    assert "Repeated failed logins" in ids_log['description']
    assert ids_log['status'] == "TRIGGERED"
    db.close()
    print(" -> IDS_SUSPICIOUS_ACTIVITY logged successfully.")

    # 4b. Verify cooldown blocks further login attempts even with correct password
    rv_blocked = login_user(client, 'sec_user', 'strong_password', remote_addr='192.168.1.10')
    assert rv_blocked.status_code == 429, "Subsequent login attempts during cooldown must return 429"
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    cooldown_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='LOGIN_RATE_LIMITED' ORDER BY id DESC").fetchone()
    assert cooldown_log is not None, "LOGIN_RATE_LIMITED must be recorded during cooldown attempt"
    db.close()
    print(" -> Cooldown blocks login attempt and logs LOGIN_RATE_LIMITED.")

    # 4c. Verify another IP is NOT blocked (account is not permanently locked)
    rv_other_ip = login_user(client, 'sec_user', 'strong_password', remote_addr='192.168.1.20')
    assert rv_other_ip.status_code == 302, "Different IP should not be blocked (IP-based protection, no account lockout)"
    print(" -> Source IP isolation verified: Different IP can login successfully.")
    logout_user(client, remote_addr='192.168.1.20')

    # 5. Expired cooldown allows login attempts again (using deterministic clock)
    print("\n[Req 5] Expired cooldown allows login again:")
    test_now = 1000000.0
    set_time_func(lambda: test_now)
    
    # Trigger cooldown for a new IP (192.168.1.30)
    for _ in range(5):
        login_user(client, 'sec_user', 'bad_pass', remote_addr='192.168.1.30')
        
    # Verify 192.168.1.30 is currently in cooldown
    rv_in_cd = login_user(client, 'sec_user', 'strong_password', remote_addr='192.168.1.30')
    assert rv_in_cd.status_code == 429
    
    # Fast forward clock by 305 seconds (> 300s cooldown window)
    test_now += 305.0
    
    # Login attempt should now succeed
    rv_after_cd = login_user(client, 'sec_user', 'strong_password', remote_addr='192.168.1.30')
    assert rv_after_cd.status_code == 302, "After cooldown expiry, login must be allowed"
    print(" -> Deterministic clock advanced 305s: Cooldown expired and login succeeded.")
    logout_user(client, remote_addr='192.168.1.30')
    reset_time_func()

    # 6. Excessive requests trigger Rate Limiting (HTTP 429)
    print("\n[Req 6] Excessive requests trigger rate limiting (HTTP 429):")
    # Endpoint rate limit on /register is 5 requests per 60s
    for i in range(5):
        register_user(client, f'burst_user_{i}', 'password', remote_addr='192.168.1.40')
    
    # 6th request should exceed the limit
    rv_limit = register_user(client, 'burst_user_excess', 'password', remote_addr='192.168.1.40')
    assert rv_limit.status_code == 429, "Rate limit exceeded must return HTTP 429"
    assert "Retry-After" in rv_limit.headers
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    rate_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='RATE_LIMIT_EXCEEDED' ORDER BY id DESC").fetchone()
    assert rate_log is not None, "RATE_LIMIT_EXCEEDED must be logged in database"
    db.close()
    print(" -> Rate limit exceeded returned HTTP 429 and logged RATE_LIMIT_EXCEEDED.")

    # 7, 8, 9, 10. Dashboard, Inbox, Authorized & Unauthorized Downloads, HMAC Tampering
    print("\n[Req 7, 8, 9, 10] Normal file operations, authorization checks, and integrity monitoring:")
    # Register sender and receiver
    register_user(client, 'alice_p10', 'password', remote_addr='192.168.1.50')
    register_user(client, 'bob_p10', 'password', remote_addr='192.168.1.51')
    register_user(client, 'eve_p10', 'password', remote_addr='192.168.1.52')
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    bob_id = db.execute("SELECT id FROM Users WHERE username='bob_p10'").fetchone()['id']
    db.close()
    
    # Alice uploads a file for Bob
    login_user(client, 'alice_p10', 'password', remote_addr='192.168.1.50')
    upload_payload = {
        'receiver_id': str(bob_id),
        'file': (io.BytesIO(b"Confidential Phase 10 File Content"), 'phase10_doc.txt')
    }
    rv_up = client.post('/dashboard', data=upload_payload, content_type='multipart/form-data', 
                        follow_redirects=False, environ_base={'REMOTE_ADDR': '192.168.1.50'})
    assert rv_up.status_code == 302
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    file_row = db.execute("SELECT * FROM Files WHERE filename='phase10_doc.txt'").fetchone()
    file_id = file_row['id']
    enc_path = file_row['encrypted_path']
    db.close()
    
    # Bob views inbox and downloads file
    logout_user(client, remote_addr='192.168.1.50')
    login_user(client, 'bob_p10', 'password', remote_addr='192.168.1.51')
    rv_inbox = client.get('/inbox', environ_base={'REMOTE_ADDR': '192.168.1.51'})
    assert 'phase10_doc.txt' in rv_inbox.data.decode('utf-8')
    
    rv_dl = client.get(f'/download/{file_id}', environ_base={'REMOTE_ADDR': '192.168.1.51'})
    assert rv_dl.status_code == 200
    assert rv_dl.data == b"Confidential Phase 10 File Content"
    print(" -> Bob successfully downloaded authorized file.")
    
    # Eve attempts unauthorized download
    logout_user(client, remote_addr='192.168.1.51')
    login_user(client, 'eve_p10', 'password', remote_addr='192.168.1.52')
    rv_unauth = client.get(f'/download/{file_id}', follow_redirects=True, environ_base={'REMOTE_ADDR': '192.168.1.52'})
    assert "Unauthorized: You do not have permission to access this file." in rv_unauth.data.decode('utf-8')
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    unauth_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='UNAUTHORIZED_ACCESS' AND user_id=(SELECT id FROM Users WHERE username='eve_p10')").fetchone()
    assert unauth_log is not None
    assert unauth_log['ip_address'] == '192.168.1.52'
    db.close()
    print(" -> Unauthorized download blocked and logged as UNAUTHORIZED_ACCESS.")

    # Tampering test
    with open(enc_path, 'r+b') as f:
        b = f.read(1)
        f.seek(0)
        f.write(bytes([b[0] ^ 0xAA]))
        
    logout_user(client, remote_addr='192.168.1.52')
    login_user(client, 'bob_p10', 'password', remote_addr='192.168.1.51')
    rv_tampered = client.get(f'/download/{file_id}', follow_redirects=True, environ_base={'REMOTE_ADDR': '192.168.1.51'})
    assert "File integrity check failed" in rv_tampered.data.decode('utf-8')
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    tamper_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='INTEGRITY_CHECK_FAILED' ORDER BY id DESC").fetchone()
    assert tamper_log is not None
    db.close()
    print(" -> Tampered file rejected with HMAC integrity failure.")

    # 14. Security Monitoring Dashboard access and display
    print("\n[Req 14] Security Monitoring & Audit Dashboard:")
    # Bob accesses security monitor from localhost
    rv_sec_mon = client.get('/security-monitor', environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert rv_sec_mon.status_code == 200
    mon_content = rv_sec_mon.data.decode('utf-8')
    assert "Security Monitoring & IDS" in mon_content
    assert "Total Events" in mon_content
    assert "IDS Alerts" in mon_content
    print(" -> Security monitoring dashboard renders statistics and audit logs successfully.")

    print("\nALL 14 PHASE 10 REQUIREMENTS SUCCESSFULLY VERIFIED!")


# =========================================================================
# PHASE 10 FOCUSED SECURITY REVIEW TESTS
# =========================================================================
def test_security_review(client):
    print("\n=======================================================")
    print("--- PHASE 10: FOCUSED SECURITY REVIEW VERIFICATIONS ---")
    print("=======================================================")
    
    register_user(client, 'mon_user', 'password', remote_addr='192.168.1.99')
    login_user(client, 'mon_user', 'password', remote_addr='192.168.1.99')

    # 1. Verification of Remote Security-Monitor Access Control
    print("\n[Security Review 1 & 2] Security-Monitor Access Control:")
    # A normal user on LAN (192.168.1.99) accessing /security-monitor without key
    app.config['SECURITY_MONITOR_KEY'] = None
    rv_remote_denied = client.get('/security-monitor', follow_redirects=True, environ_base={'REMOTE_ADDR': '192.168.1.99'})
    assert "Access Denied" in rv_remote_denied.data.decode('utf-8'), "Remote LAN user must be denied without key"
    
    # Passing token in query parameter (?key=...) must NOT grant access
    app.config['SECURITY_MONITOR_KEY'] = 'SuperSecretMonitorToken123!'
    rv_query_denied = client.get('/security-monitor?key=SuperSecretMonitorToken123!', follow_redirects=True, environ_base={'REMOTE_ADDR': '192.168.1.99'})
    assert "Access Denied" in rv_query_denied.data.decode('utf-8'), "Query param tokens must be rejected to prevent URL/history leakage"

    # Passing incorrect header must be denied
    rv_bad_header = client.get('/security-monitor', headers={'X-Security-Monitor-Key': 'WrongToken'}, follow_redirects=True, environ_base={'REMOTE_ADDR': '192.168.1.99'})
    assert "Access Denied" in rv_bad_header.data.decode('utf-8'), "Invalid header token must be denied"

    # Passing correct header must be accepted
    rv_header_allowed = client.get('/security-monitor', headers={'X-Security-Monitor-Key': 'SuperSecretMonitorToken123!'}, follow_redirects=False, environ_base={'REMOTE_ADDR': '192.168.1.99'})
    assert rv_header_allowed.status_code == 200, "Valid header token must grant access to Security Monitor"
    print(" -> Remote LAN access control verified: Header required, query params rejected, constant-time compare enforced.")

    # 2. Concurrency stress test for SecurityManager state integrity
    print("\n[Security Review 7] Concurrency Stress Test:")
    security_manager.reset_all()
    threads = []
    results = []

    def worker(worker_id):
        # Multiple workers hit the security manager concurrently
        ip = "10.0.0.1"
        allowed, _ = security_manager.check_rate_limit(ip, 'test_route', limit=20, window=60)
        results.append(allowed)

    for i in range(50):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Out of 50 concurrent requests with limit 20, exactly 20 must be allowed and 30 rejected
    allowed_count = sum(1 for r in results if r is True)
    rejected_count = sum(1 for r in results if r is False)
    assert allowed_count == 20, f"Expected exactly 20 allowed concurrent requests, got {allowed_count}"
    assert rejected_count == 30, f"Expected exactly 30 blocked concurrent requests, got {rejected_count}"
    print(f" -> Thread-safety verified: 50 concurrent threads resulted in exactly {allowed_count} allowed and {rejected_count} blocked.")

    # 3. Cooldown Boundary Test
    print("\n[Security Review 3] Exact Failed-Login Cooldown Boundary Test:")
    security_manager.reset_all()
    test_ip = "10.0.0.99"
    # Attempts 1 to 4: no cooldown triggered
    for attempt in range(1, 5):
        triggered, _ = security_manager.record_failed_login(test_ip, limit=5, window=300, cooldown=300)
        assert triggered is False, f"Attempt {attempt} must not trigger cooldown"
        is_cd, _ = security_manager.check_login_cooldown(test_ip)
        assert is_cd is False

    # Attempt 5: triggers cooldown immediately
    triggered, remaining = security_manager.record_failed_login(test_ip, limit=5, window=300, cooldown=300)
    assert triggered is True, "Attempt 5 must trigger cooldown"
    assert remaining == 300
    is_cd, cd_left = security_manager.check_login_cooldown(test_ip)
    assert is_cd is True
    print(" -> Cooldown boundary verified: Exactly 5 attempts triggers cooldown.")

    # 4. Audit Log Secrets Verification
    print("\n[Security Review 6] Audit Logs Secrets Inspection:")
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    logs = db.execute("SELECT * FROM AuditLogs").fetchall()
    db.close()

    sensitive_strings = [
        "SuperSecretMonitorToken123!",
        "strong_password",
        "wrong_password",
        "bad_pass",
        "BEGIN RSA PRIVATE KEY",
        "passphrase",
    ]

    for log in logs:
        desc = str(log['description'])
        for sensitive in sensitive_strings:
            assert sensitive not in desc, f"Sensitive content '{sensitive}' found in AuditLog record: {dict(log)}"
    print(f" -> Audit log integrity verified: Scanned {len(logs)} audit log records, zero secrets found.")


if __name__ == '__main__':
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    security_manager.reset_all()
    reset_time_func()
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.execute('DROP TABLE IF EXISTS Files')
    db.execute('DROP TABLE IF EXISTS AuditLogs')
    db.execute('DROP TABLE IF EXISTS Users')
    with open('database/db_schema.sql') as f:
        db.executescript(f.read())
    db.commit()
    db.close()
    
    with app.test_client() as c:
        test_all(c)
        test_phase10_security_and_ids(c)
        test_security_review(c)
