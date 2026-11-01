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


# =============================================================================
# 1. AUTHENTICATION AND SESSION SECURITY TESTS
# =============================================================================
def test_authentication_and_session_security(client):
    print("\n--- 1. Authentication & Session Security Tests ---")
    
    # Unauthenticated access to protected endpoints must be rejected / redirected to login
    protected_endpoints = ['/dashboard', '/inbox', '/download/1', '/security-monitor']
    for ep in protected_endpoints:
        rv = client.get(ep, follow_redirects=False)
        assert rv.status_code == 302, f"Unauthenticated access to {ep} should redirect (302)"
        assert rv.headers.get('Location').endswith('/login')
        print(f" -> Protected route {ep} denied to unauthenticated user (Redirected to login).")

    # Registration & valid login
    register_user(client, 'auth_alice', 'CorrectPass123!')
    rv_login = login_user(client, 'auth_alice', 'CorrectPass123!')
    assert rv_login.status_code == 302
    assert rv_login.headers.get('Location').endswith('/dashboard')
    
    # Session cookie validation (HttpOnly, no password or plaintext keys in cookie)
    cookies = rv_login.headers.getlist('Set-Cookie')
    session_cookie = next((c for c in cookies if c.startswith('session=')), '')
    assert session_cookie != '', "Session cookie should be generated on login"
    assert 'CorrectPass123!' not in session_cookie, "Plaintext password must never be in session cookie!"
    assert 'BEGIN RSA PRIVATE KEY' not in session_cookie
    assert 'HttpOnly' in session_cookie
    print(" -> Session cookie verified: HttpOnly set, zero passwords or private keys exposed.")

    # Incorrect credentials do not create session
    logout_user(client)
    rv_bad_login = login_user(client, 'auth_alice', 'WrongPassword456!')
    assert rv_bad_login.status_code in (200, 401)
    # Trying to access dashboard without session must fail
    rv_dash = client.get('/dashboard', follow_redirects=False)
    assert rv_dash.status_code == 302
    print(" -> Bad login rejected without session creation.")

    # Logout invalidates previous session
    login_user(client, 'auth_alice', 'CorrectPass123!')
    rv_dash_auth = client.get('/dashboard', follow_redirects=False)
    assert rv_dash_auth.status_code == 200
    logout_user(client)
    rv_dash_after_logout = client.get('/dashboard', follow_redirects=False)
    assert rv_dash_after_logout.status_code == 302
    assert rv_dash_after_logout.headers.get('Location').endswith('/login')
    print(" -> Logout verified: Session terminated cleanly.")


# =============================================================================
# 2. AUTHORIZATION AND ACCESS CONTROL TESTS
# =============================================================================
def test_authorization_and_access_control(client):
    print("\n--- 2. Authorization & Access Control Tests ---")
    register_user(client, 'user_alice', 'pass_alice')
    register_user(client, 'user_bob', 'pass_bob')
    register_user(client, 'user_charlie', 'pass_charlie')

    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    bob_id = db.execute("SELECT id FROM Users WHERE username='user_bob'").fetchone()['id']
    charlie_id = db.execute("SELECT id FROM Users WHERE username='user_charlie'").fetchone()['id']
    db.close()

    # Alice uploads a secret file intended solely for Bob
    login_user(client, 'user_alice', 'pass_alice')
    upload_data = {
        'receiver_id': str(bob_id),
        'file': (io.BytesIO(b"Top Secret For Bob Only!"), 'for_bob.txt')
    }
    rv_up = client.post('/dashboard', data=upload_data, content_type='multipart/form-data', follow_redirects=False)
    assert rv_up.status_code == 302
    logout_user(client)

    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    file_record = db.execute("SELECT * FROM Files WHERE filename='for_bob.txt'").fetchone()
    file_id = file_record['id']
    db.close()

    # Bob (authorized receiver) downloads the file
    login_user(client, 'user_bob', 'pass_bob')
    rv_bob_dl = client.get(f'/download/{file_id}', follow_redirects=False)
    assert rv_bob_dl.status_code == 200
    assert rv_bob_dl.data == b"Top Secret For Bob Only!"
    print(f" -> Authorized access: Bob successfully downloaded file #{file_id}.")
    logout_user(client)

    # Charlie (unauthorized) attempts to download Bob's file by guessing file ID
    login_user(client, 'user_charlie', 'pass_charlie')
    rv_charlie_dl = client.get(f'/download/{file_id}', follow_redirects=True)
    assert b"Top Secret For Bob Only!" not in rv_charlie_dl.data, "Plaintext must NEVER be delivered to unauthorized user!"
    assert "Unauthorized" in rv_charlie_dl.data.decode('utf-8')
    
    # Verify UNAUTHORIZED_ACCESS event in database
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    unauth_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='UNAUTHORIZED_ACCESS' AND user_id=?", (charlie_id,)).fetchone()
    assert unauth_log is not None
    assert f"file_id {file_id}" in unauth_log['description']
    db.close()
    print(" -> Authorization rejection verified: Charlie blocked from downloading Bob's file, event logged.")
    logout_user(client)


# =============================================================================
# 3. FILE ENCRYPTION AND INTEGRITY TESTS
# =============================================================================
def test_file_encryption_and_integrity(client):
    print("\n--- 3. File Encryption & Integrity Tests ---")
    register_user(client, 'crypto_alice', 'pass_alice')
    register_user(client, 'crypto_bob', 'pass_bob')

    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    bob_id = db.execute("SELECT id FROM Users WHERE username='crypto_bob'").fetchone()['id']
    db.close()

    # Test fixtures across text, image, audio, video, binary
    fixtures = [
        ('sec_doc.txt', b'Encrypted document payload content 12345'),
        ('sec_img.png', b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' + os.urandom(32)),
        ('sec_audio.wav', b'RIFF' + struct.pack('<I', 100) + b'WAVEfmt ' + os.urandom(64)),
        ('sec_video.mp4', b'\x00\x00\x00\x20ftypisom' + os.urandom(128)),
        ('sec_bin.dat', os.urandom(2048))
    ]

    for fname, raw_bytes in fixtures:
        security_manager.reset_all()
        logout_user(client)
        login_user(client, 'crypto_alice', 'pass_alice')
        upload_data = {
            'receiver_id': str(bob_id),
            'file': (io.BytesIO(raw_bytes), fname)
        }
        client.post('/dashboard', data=upload_data, content_type='multipart/form-data', follow_redirects=False)

        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        rec = db.execute("SELECT * FROM Files WHERE filename=? ORDER BY id DESC", (fname,)).fetchone()
        f_id = rec['id']
        enc_path = rec['encrypted_path']
        db.close()

        # 1. Stored data is ciphertext, not plaintext
        with open(enc_path, 'rb') as f:
            disk_bytes = f.read()
        assert raw_bytes not in disk_bytes, f"Plaintext must not be on disk for {fname}"

        # 2. Authorized download reproduces byte-for-byte exact data
        logout_user(client)
        login_user(client, 'crypto_bob', 'pass_bob')
        rv_dl = client.get(f'/download/{f_id}', follow_redirects=False)
        assert rv_dl.status_code == 200
        assert rv_dl.data == raw_bytes, f"Byte match failed for {fname}"
        print(f" -> Verified encryption & byte-for-byte decryption for {fname}.")

    # 3. Tampering with ciphertext: HMAC must fail BEFORE decryption
    with open(enc_path, 'r+b') as f:
        f.seek(10)
        byte_val = f.read(1)
        f.seek(10)
        f.write(bytes([byte_val[0] ^ 0xFF]))

    rv_tampered = client.get(f'/download/{f_id}', follow_redirects=True)
    assert "File integrity check failed" in rv_tampered.data.decode('utf-8')
    assert raw_bytes not in rv_tampered.data, "Tampered plaintext must NEVER be delivered"
    
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    t_log = db.execute("SELECT * FROM AuditLogs WHERE event_type='INTEGRITY_CHECK_FAILED' ORDER BY id DESC").fetchone()
    assert t_log is not None
    db.close()
    print(" -> Integrity verification verified: Tampered ciphertext rejected before decryption.")


# =============================================================================
# 4. INPUT VALIDATION AND FILE-HANDLING SECURITY TESTS
# =============================================================================
def test_input_validation_and_file_handling(client):
    print("\n--- 4. Input Validation & File Handling Tests ---")
    register_user(client, 'inp_alice', 'pass_alice')
    register_user(client, 'inp_bob', 'pass_bob')

    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    bob_id = db.execute("SELECT id FROM Users WHERE username='inp_bob'").fetchone()['id']
    db.close()

    login_user(client, 'inp_alice', 'pass_alice')

    # Path traversal attack filename (../../app.py or ../config.py)
    traversal_data = {
        'receiver_id': str(bob_id),
        'file': (io.BytesIO(b"Malicious Path Traversal Attempt"), '../../app.py')
    }
    client.post('/dashboard', data=traversal_data, content_type='multipart/form-data', follow_redirects=False)

    # Verify that app.py was not overwritten
    with open('app.py', 'r', encoding='utf-8') as f:
        app_content = f.read()
    assert "Malicious Path Traversal Attempt" not in app_content
    assert "from flask import Flask" in app_content
    print(" -> Path traversal defense verified: Filename securely sanitized and app.py unharmed.")

    # Empty filename and malformed requests
    empty_data = {
        'receiver_id': str(bob_id),
        'file': (io.BytesIO(b""), '')
    }
    rv_empty = client.post('/dashboard', data=empty_data, content_type='multipart/form-data', follow_redirects=False)
    assert rv_empty.status_code == 302
    
    # Missing receiver ID
    no_rec_data = {
        'receiver_id': '',
        'file': (io.BytesIO(b"No Receiver"), 'test.txt')
    }
    rv_no_rec = client.post('/dashboard', data=no_rec_data, content_type='multipart/form-data', follow_redirects=False)
    assert rv_no_rec.status_code == 302

    # Non-existent file ID download
    rv_404_file = client.get('/download/999999', follow_redirects=True)
    assert "File not found" in rv_404_file.data.decode('utf-8')
    print(" -> Input validation verified: Empty filenames, missing receivers, and invalid IDs handled safely.")


# =============================================================================
# 5. INTRUSION DETECTION AND AVAILABILITY CONTROLS TESTS
# =============================================================================
def test_ids_and_availability_controls(client):
    print("\n--- 5. Intrusion Detection & Availability Controls Tests ---")
    register_user(client, 'ids_target_user', 'TargetPass123!', remote_addr='10.10.10.5')

    # 1. Repeated failed logins trigger threshold (5) and activate cooldown
    for i in range(1, 6):
        rv_fail = login_user(client, 'ids_target_user', 'WrongPass', remote_addr='10.10.10.5')
        if i == 5:
            assert rv_fail.status_code == 429
            print(" -> 5th consecutive failed login triggered login cooldown (429).")

    # Cooldown blocks further attempts from this IP
    rv_cd_blocked = login_user(client, 'ids_target_user', 'TargetPass123!', remote_addr='10.10.10.5')
    assert rv_cd_blocked.status_code == 429

    # Source IP isolation (another IP is unaffected)
    rv_other = login_user(client, 'ids_target_user', 'TargetPass123!', remote_addr='10.10.10.6')
    assert rv_other.status_code == 302
    logout_user(client, remote_addr='10.10.10.6')
    print(" -> Cooldown IP isolation verified: Distinct IP not blocked.")

    # Expired cooldown permits login again
    test_clock = 2000000.0
    set_time_func(lambda: test_clock)
    # Trigger cooldown on 10.10.10.7
    for _ in range(5):
        login_user(client, 'ids_target_user', 'Bad', remote_addr='10.10.10.7')
    assert login_user(client, 'ids_target_user', 'TargetPass123!', remote_addr='10.10.10.7').status_code == 429
    
    # Advance clock by 305s
    test_clock += 305.0
    rv_restored = login_user(client, 'ids_target_user', 'TargetPass123!', remote_addr='10.10.10.7')
    assert rv_restored.status_code == 302
    print(" -> Cooldown expiration verified: Login capability deterministically restored after timeout.")
    logout_user(client, remote_addr='10.10.10.7')
    reset_time_func()

    # 2. Concurrency stress test on Rate Limiter
    security_manager.reset_all()
    threads = []
    outcomes = []
    
    def stress_worker():
        ok, _ = security_manager.check_rate_limit('10.20.30.40', 'global', limit=25, window=60)
        outcomes.append(ok)

    for _ in range(60):
        t = threading.Thread(target=stress_worker)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for o in outcomes if o is True) == 25
    assert sum(1 for o in outcomes if o is False) == 35
    print(" -> Rate limiter concurrency stress test passed: Exact limit enforced across 60 concurrent threads.")


# =============================================================================
# 6. AUDIT LOGS AND ERROR HANDLING TESTS
# =============================================================================
def test_audit_logs_and_error_handling(client):
    print("\n--- 6. Audit Logs & Error Handling Tests ---")
    register_user(client, 'audit_user', 'SuperSecretPass#99')
    login_user(client, 'audit_user', 'SuperSecretPass#99')

    # Scan SQLite AuditLogs table for sensitive secrets
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    records = db.execute("SELECT * FROM AuditLogs").fetchall()
    db.close()

    banned_substrings = [
        "SuperSecretPass#99",
        "BEGIN RSA PRIVATE KEY",
        "scryptAndAES128-CBC",
        "passphrase="
    ]

    for rec in records:
        desc = str(rec['description'])
        for banned in banned_substrings:
            assert banned not in desc, f"Found secret '{banned}' in audit log #{rec['id']}"
    print(f" -> Audit log safety verified: {len(records)} audit records scanned; zero secrets found.")

    # Escape test in Security Monitor template
    # Insert an audit log with XSS payload in description
    db = sqlite3.connect(app.config['DATABASE'])
    db.execute(
        "INSERT INTO AuditLogs (user_id, ip_address, event_type, status, description) VALUES (1, '127.0.0.1', 'SECURITY_TEST', 'SUCCESS', '<script>alert(1)</script>')",
    )
    db.commit()
    db.close()

    rv_mon = client.get('/security-monitor', environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert rv_mon.status_code == 200
    mon_html = rv_mon.data.decode('utf-8')
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in mon_html or "<script>alert(1)</script>" not in mon_html
    print(" -> User-controlled text escaping verified in Security Monitor dashboard.")


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
        test_authentication_and_session_security(c)
        test_authorization_and_access_control(c)
        test_file_encryption_and_integrity(c)
        test_input_validation_and_file_handling(c)
        test_ids_and_availability_controls(c)
        test_audit_logs_and_error_handling(c)
