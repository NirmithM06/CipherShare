"""
Comprehensive Timestamp Handling Verification for CipherShare
Tests all 10 points specified in the user request.
"""
import os
import sys
import io
import time
from datetime import datetime, timezone, timedelta

# Ensure CipherShare root is on path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from database.models import get_db_connection
from core.time_utils import (
    utc_now,
    utc_now_str,
    parse_utc_timestamp,
    utc_to_ist,
    format_ist,
    time_ago,
    IST
)

def run_tests():
    print("=" * 70)
    print("CIPHERSHARE TIMESTAMP HANDLING VERIFICATION")
    print("=" * 70)
    
    passed_tests = 0
    total_tests = 10
    client = app.test_client()

    # -------------------------------------------------------------
    # Test 10: Verify UTC-to-IST Conversion Logic First
    # -------------------------------------------------------------
    print("\n[TEST 10] Verifying UTC-to-IST conversion and edge cases...")
    test_utc_str = "2026-10-30 20:00:00"
    ist_dt = utc_to_ist(test_utc_str)
    assert ist_dt.hour == 1 and ist_dt.minute == 30 and ist_dt.day == 31, f"Expected 01:30 AM on 31 Oct, got {ist_dt}"
    
    formatted = format_ist(test_utc_str)
    assert formatted == "31 Oct 2026, 01:30:00 AM IST", f"Formatted IST mismatch: {formatted}"
    
    # ISO string with Z
    iso_utc = "2026-10-30T20:00:00Z"
    assert format_ist(iso_utc) == "31 Oct 2026, 01:30:00 AM IST"
    
    # Missing / None
    assert format_ist(None) == "Not available"
    assert format_ist("") == "Not available"
    
    # Relative time
    now_utc = utc_now_str()
    assert time_ago(now_utc) == "Just now"
    
    old_utc = (utc_now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    assert time_ago(old_utc) == "5 mins ago"
    
    print("  [PASS] UTC-to-IST conversion (+05:30), ISO support, fallbacks and time_ago all verified!")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 1: Registration Timestamp
    # -------------------------------------------------------------
    print("\n[TEST 1] Verifying registration timestamp handling...")
    test_user = f"ts_user_{int(time.time())}"
    test_pass = "TestPass123!"
    t_before_reg = utc_now()
    
    resp = client.post('/register', data={'username': test_user, 'password': test_pass}, follow_redirects=True)
    assert resp.status_code == 200, f"Register failed: {resp.status_code}"
    
    db = get_db_connection()
    user_row = db.execute("SELECT id FROM Users WHERE username = ?", (test_user,)).fetchone()
    assert user_row is not None, "Registered user not found in Users"
    user_id = user_row['id']
    
    log_row = db.execute(
        "SELECT * FROM AuditLogs WHERE user_id = ? AND event_type = 'REGISTER' ORDER BY id DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    db.close()
    
    assert log_row is not None, "REGISTER audit log not found"
    reg_ts = parse_utc_timestamp(log_row['timestamp'])
    assert reg_ts is not None, f"Could not parse registration timestamp: {log_row['timestamp']}"
    diff_reg = abs((reg_ts - t_before_reg).total_seconds())
    assert diff_reg < 10, f"Registration timestamp difference too large: {diff_reg}s"
    print(f"  [PASS] Registration UTC timestamp: {log_row['timestamp']} -> IST: {format_ist(log_row['timestamp'])} (diff: {diff_reg:.2f}s)")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 2: Login Timestamp
    # -------------------------------------------------------------
    print("\n[TEST 2] Verifying login timestamp handling...")
    t_before_login = utc_now()
    with client.session_transaction() as sess:
        sess.clear()
        
    resp = client.post('/login', data={'username': test_user, 'password': test_pass}, follow_redirects=True)
    assert resp.status_code == 200, f"Login failed: {resp.status_code}"
    
    db = get_db_connection()
    login_log = db.execute(
        "SELECT * FROM AuditLogs WHERE user_id = ? AND event_type = 'LOGIN_SUCCESS' ORDER BY id DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    db.close()
    
    assert login_log is not None, "LOGIN_SUCCESS audit log not found"
    login_ts = parse_utc_timestamp(login_log['timestamp'])
    assert login_ts is not None, f"Could not parse login timestamp: {login_log['timestamp']}"
    diff_login = abs((login_ts - t_before_login).total_seconds())
    assert diff_login < 10, f"Login timestamp diff too large: {diff_login}s"
    print(f"  [PASS] Login UTC timestamp: {login_log['timestamp']} -> IST: {format_ist(login_log['timestamp'])} (diff: {diff_login:.2f}s)")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 3: File Upload Timestamp
    # -------------------------------------------------------------
    print("\n[TEST 3] Verifying file upload timestamp handling...")
    # Register recipient Bob for testing upload
    bob_user = f"ts_bob_{int(time.time())}"
    client.post('/register', data={'username': bob_user, 'password': test_pass}, follow_redirects=True)
    
    db = get_db_connection()
    bob_row = db.execute("SELECT id FROM Users WHERE username = ?", (bob_user,)).fetchone()
    bob_id = bob_row['id']
    db.close()
    
    # Login back as test_user
    client.post('/login', data={'username': test_user, 'password': test_pass}, follow_redirects=True)
    
    t_before_upload = utc_now()
    upload_data = {
        'receiver_id': bob_id,
        'file': (io.BytesIO(b"Confidential timestamp test document content"), "timestamp_doc.txt")
    }
    resp = client.post('/dashboard', data=upload_data, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200, f"Upload request failed: {resp.status_code}"
    
    db = get_db_connection()
    file_row = db.execute(
        "SELECT * FROM Files WHERE sender_id = ? AND filename = 'timestamp_doc.txt' ORDER BY id DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    db.close()
    
    assert file_row is not None, "Uploaded file record not found"
    file_ts = parse_utc_timestamp(file_row['timestamp'])
    assert file_ts is not None, f"Could not parse file timestamp: {file_row['timestamp']}"
    diff_upload = abs((file_ts - t_before_upload).total_seconds())
    assert diff_upload < 10, f"Upload timestamp diff too large: {diff_upload}s"
    print(f"  [PASS] File Upload UTC timestamp: {file_row['timestamp']} -> IST: {format_ist(file_row['timestamp'])} (diff: {diff_upload:.2f}s)")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 4: Inbox Received Timestamp Display
    # -------------------------------------------------------------
    print("\n[TEST 4] Verifying inbox received timestamp display...")
    # Login as Bob
    client.post('/login', data={'username': bob_user, 'password': test_pass}, follow_redirects=True)
    resp = client.get('/inbox')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')
    
    expected_ist = format_ist(file_row['timestamp'])
    assert 'Sent:' in html, "Inbox missing 'Sent:' prefix"
    assert expected_ist in html, f"Expected formatted IST timestamp '{expected_ist}' in inbox HTML"
    print(f"  [PASS] Inbox displays accurate IST timestamp: '{expected_ist}' with 'Sent:' label")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 5: Signature Generation & Verification Timestamps
    # -------------------------------------------------------------
    print("\n[TEST 5] Verifying digital signature timestamps & details API...")
    t_before_sig = utc_now()
    sig_resp = client.post('/api/signature/generate', json={'message': 'Verify IST time handling'})
    assert sig_resp.status_code == 200
    sig_data = sig_resp.get_json()
    
    db = get_db_connection()
    sig_row = db.execute(
        "SELECT * FROM DigitalSignatures WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (bob_id,)
    ).fetchone()
    db.close()
    
    assert sig_row is not None, "Signature not found in DigitalSignatures"
    sig_ts = parse_utc_timestamp(sig_row['timestamp'])
    assert sig_ts is not None
    diff_sig = abs((sig_ts - t_before_sig).total_seconds())
    assert diff_sig < 10, f"Signature timestamp diff too large: {diff_sig}s"
    
    # Test /api/file/details/<file_id> returns proper timestamps
    details_resp = client.get(f"/api/file/details/{file_row['id']}")
    assert details_resp.status_code == 200
    details = details_resp.get_json()
    assert details['timestamp'] == file_row['timestamp']
    assert details['timestamp_ist'] == format_ist(file_row['timestamp'])
    print(f"  [PASS] Signature UTC timestamp: {sig_row['timestamp']} -> IST: {format_ist(sig_row['timestamp'])}")
    print(f"  [PASS] Details API returns both UTC and IST timestamps correctly")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 6: Audit Log Timestamps
    # -------------------------------------------------------------
    print("\n[TEST 6] Verifying audit log timestamps and UI formatting...")
    db = get_db_connection()
    logs = db.execute("SELECT * FROM AuditLogs ORDER BY id DESC LIMIT 10").fetchall()
    db.close()
    
    assert len(logs) > 0, "No audit logs found"
    for l in logs:
        parsed = parse_utc_timestamp(l['timestamp'])
        assert parsed is not None, f"Audit log #{l['id']} has invalid timestamp: {l['timestamp']}"
    
    # Test overview page renders IST audit logs
    overview_resp = client.get('/overview')
    assert overview_resp.status_code == 200
    overview_html = overview_resp.data.decode('utf-8')
    latest_log_ist = format_ist(logs[0]['timestamp'])
    assert latest_log_ist in overview_html, f"Overview page missing formatted IST timestamp: {latest_log_ist}"
    print(f"  [PASS] Audit logs validated. Overview table accurately renders: {latest_log_ist}")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 7: Security Monitoring Timestamps
    # -------------------------------------------------------------
    print("\n[TEST 7] Verifying security monitoring timestamps...")
    # Trigger a negative security event: failed login
    t_before_fail = utc_now()
    client.post('/login', data={'username': 'non_existent_user', 'password': 'wrong_password'}, follow_redirects=True)
    
    db = get_db_connection()
    fail_log = db.execute(
        "SELECT * FROM AuditLogs WHERE event_type = 'LOGIN_FAILURE' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()
    
    assert fail_log is not None, "Failed login log not found"
    fail_ts = parse_utc_timestamp(fail_log['timestamp'])
    diff_fail = abs((fail_ts - t_before_fail).total_seconds())
    assert diff_fail < 10, f"Failed login timestamp diff too large: {diff_fail}s"
    
    # Login back as Bob to view security monitor
    client.post('/login', data={'username': bob_user, 'password': test_pass}, follow_redirects=True)
    sec_resp = client.get('/security-monitor')
    assert sec_resp.status_code == 200
    sec_html = sec_resp.data.decode('utf-8')
    fail_log_ist = format_ist(fail_log['timestamp'])
    assert fail_log_ist in sec_html, f"Security monitor missing failed login IST timestamp: {fail_log_ist}"
    print(f"  [PASS] Security monitor renders negative event with accurate IST timestamp: {fail_log_ist}")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 8: Performance Event Timestamps
    # -------------------------------------------------------------
    print("\n[TEST 8] Verifying performance event timestamps...")
    db = get_db_connection()
    perf_row = db.execute(
        "SELECT * FROM PerformanceMetrics WHERE operation_type = 'UPLOAD' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()
    
    assert perf_row is not None, "Upload performance row not found"
    perf_ts = parse_utc_timestamp(perf_row['timestamp'])
    assert perf_ts is not None, f"Could not parse performance timestamp: {perf_row['timestamp']}"
    
    # Check /api/performance/file-sharing API
    perf_api_resp = client.get('/api/performance/file-sharing')
    assert perf_api_resp.status_code == 200
    perf_data = perf_api_resp.get_json()
    assert len(perf_data) > 0
    assert perf_data[0]['timestamp'] is not None
    print(f"  [PASS] Performance metrics recorded with valid UTC timestamp: {perf_row['timestamp']} -> IST: {format_ist(perf_row['timestamp'])}")
    passed_tests += 1

    # -------------------------------------------------------------
    # Test 9: Persistence Check
    # -------------------------------------------------------------
    print("\n[TEST 9] Verifying database persistence across connection resets...")
    db1 = get_db_connection()
    db1.execute("SELECT 1").fetchone()
    db1.close()
    
    db2 = get_db_connection()
    re_file = db2.execute("SELECT * FROM Files WHERE id = ?", (file_row['id'],)).fetchone()
    re_sig = db2.execute("SELECT * FROM DigitalSignatures WHERE id = ?", (sig_row['id'],)).fetchone()
    re_log = db2.execute("SELECT * FROM AuditLogs WHERE id = ?", (login_log['id'],)).fetchone()
    db2.close()
    
    assert re_file['timestamp'] == file_row['timestamp'], "Persisted file timestamp mismatch"
    assert re_sig['timestamp'] == sig_row['timestamp'], "Persisted signature timestamp mismatch"
    assert re_log['timestamp'] == login_log['timestamp'], "Persisted log timestamp mismatch"
    print(f"  [PASS] Database records and timestamps successfully persist across connections.")
    passed_tests += 1

    print("\n" + "=" * 70)
    print(f"ALL {passed_tests}/{total_tests} TIMESTAMP VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_tests()
