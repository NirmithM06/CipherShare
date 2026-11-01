from flask import Flask, render_template, session, redirect, url_for, flash, request, send_file
from config import Config
from database.models import get_db_connection, init_db
from core.auth import auth, login_required
from core.audit import log_event, get_client_ip
from core.security import (
    security_manager,
    rate_limit,
    rate_limit_exceeded_response,
    can_access_security_monitor
)
from core.collector import live_collector
import os
import time
import uuid
from werkzeug.utils import secure_filename
from flask_session import Session
from core.time_utils import format_ist, time_ago, utc_now_str

app = Flask(__name__)
app.config.from_object(Config)

# Register Jinja2 filters for timezone handling
app.jinja_env.filters['format_ist'] = format_ist
app.jinja_env.filters['time_ago'] = time_ago

# Initialize app dependencies (like storage folders)
Config.init_app(app)

# Initialize Server-Side Session
Session(app)

# Initialize the database
with app.app_context():
    init_db()

# Register Authentication Blueprint
app.register_blueprint(auth)

# Register Cryptography & Analysis Blueprint
from core.routes import crypto_bp
app.register_blueprint(crypto_bp)


@app.before_request
def enforce_global_security_and_rate_limits():
    """
    Applies global IP request rate limiting and floods detection before routing.
    Exempts static asset delivery.
    """
    # Skip static files
    if request.path.startswith('/static'):
        return None

    client_ip = get_client_ip()
    max_reqs, win_sec = Config.RATE_LIMIT_GLOBAL
    allowed, retry_after = security_manager.check_rate_limit(client_ip, 'global', max_reqs, win_sec)
    
    if not allowed:
        user_id = session.get('user_id')
        # Log rate limit event
        log_event(
            user_id=user_id,
            event_type="RATE_LIMIT_EXCEEDED",
            status="BLOCKED",
            description=f"Global IP rate limit exceeded ({max_reqs} requests / {win_sec}s) on {request.path}"
        )
        # Record IDS alert for request flooding
        log_event(
            user_id=user_id,
            event_type="IDS_SUSPICIOUS_ACTIVITY",
            status="TRIGGERED",
            description=f"Excessive request flooding detected from IP {client_ip}."
        )
        # Record in traffic activity
        live_collector.record_traffic_event(
            ip_address=client_ip,
            endpoint=request.path,
            method=request.method,
            status_code=429,
            payload_size_bytes=0,
            event_category="RATE_LIMIT",
            details="Global rate limit exceeded"
        )
        return rate_limit_exceeded_response(
            retry_after,
            message=f"Global rate limit exceeded. Too many requests from this IP. Please wait {retry_after} seconds."
        )


@app.after_request
def record_response_traffic_activity(response):
    """
    Safely records application-level request activity for traffic analysis.
    Exempts static assets.
    """
    if not request.path.startswith('/static'):
        client_ip = get_client_ip()
        status_code = response.status_code
        payload_size = response.calculate_content_length() or 0
        
        # Categorize traffic
        if request.path in ('/dashboard', '/download') or request.path.startswith('/download/'):
            category = "FILE_TRANSFER" if request.method == 'POST' or request.path.startswith('/download/') else "APPLICATION"
        elif request.path in ('/login', '/register', '/logout'):
            category = "AUTHENTICATION"
        elif request.path == '/security-monitor':
            category = "ADMIN_MONITOR"
        elif status_code == 429:
            category = "RATE_LIMIT"
        elif status_code >= 400:
            category = "CLIENT_ERROR"
        else:
            category = "GENERAL"

        live_collector.record_traffic_event(
            ip_address=client_ip,
            endpoint=request.path,
            method=request.method,
            status_code=status_code,
            payload_size_bytes=payload_size,
            event_category=category,
            details=f"HTTP {request.method} {request.path} -> {status_code}"
        )
    return response


@app.errorhandler(429)
def handle_rate_limit_error(e):
    return render_template('429.html', message="Rate limit exceeded. Please wait before retrying.", retry_after=60), 429


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    db = get_db_connection()
    if request.method == 'POST':
        # Start high-resolution timer for total upload processing
        t_upload_start = time.perf_counter()
        
        # Apply route-level rate limiting for file uploads
        client_ip = get_client_ip()
        max_uploads, win_sec = Config.RATE_LIMIT_UPLOAD
        allowed, retry_after = security_manager.check_rate_limit(client_ip, 'upload', max_uploads, win_sec)
        if not allowed:
            db.close()
            log_event(
                user_id=session.get('user_id'),
                event_type="RATE_LIMIT_EXCEEDED",
                status="BLOCKED",
                description=f"Upload rate limit exceeded ({max_uploads} uploads / {win_sec}s) by IP {client_ip}"
            )
            live_collector.record_performance(
                operation_type="UPLOAD",
                file_size_bytes=0,
                total_duration_ms=(time.perf_counter() - t_upload_start) * 1000.0,
                status="RATE_LIMITED",
                details=f"Upload rate limit exceeded by IP {client_ip}"
            )
            return rate_limit_exceeded_response(
                retry_after,
                message=f"Upload rate limit exceeded. You can only upload {max_uploads} files per minute. Please wait {retry_after} seconds."
            )

        receiver_id = request.form.get('receiver_id')
        file = request.files.get('file')
        
        if not receiver_id or not file or file.filename == '':
            db.close()
            flash('Receiver and file are required.', 'error')
            live_collector.record_performance(
                operation_type="UPLOAD",
                file_size_bytes=0,
                total_duration_ms=(time.perf_counter() - t_upload_start) * 1000.0,
                status="VALIDATION_FAILED",
                details="Missing receiver or file"
            )
            return redirect(url_for('dashboard'))
            
        receiver_record = db.execute('SELECT public_key FROM Users WHERE id = ?', (receiver_id,)).fetchone()
        if not receiver_record or not receiver_record['public_key']:
            db.close()
            flash('Invalid receiver or receiver has no public key.', 'error')
            live_collector.record_performance(
                operation_type="UPLOAD",
                file_size_bytes=0,
                total_duration_ms=(time.perf_counter() - t_upload_start) * 1000.0,
                status="VALIDATION_FAILED",
                details="Receiver has no public key"
            )
            return redirect(url_for('dashboard'))
            
        # Read the file data
        file_data = file.read()
        file_size_bytes = len(file_data)
        
        # 1. Confidentiality & Integrity
        from core.crypto import (
            encrypt_file_data,
            compute_file_sha256,
            sign_file_hash,
            generate_signing_keypair
        )
        
        # A. Compute SHA-256 digest of original plaintext file
        file_hash, hash_time_ms = compute_file_sha256(file_data)
        
        # B. Encrypt file with AES-256-CBC, wrap AES key with RSA-OAEP, calculate HMAC-SHA256
        encrypted_data, encrypted_aes_key, iv, hmac_hash, enc_timings = encrypt_file_data(
            file_data, 
            receiver_record['public_key'],
            return_timings=True
        )
        
        # C. Retrieve or provision sender persistent signing keypair and sign file SHA-256 digest
        sender_record = db.execute('SELECT * FROM Users WHERE id = ?', (session['user_id'],)).fetchone()
        sender_spub = sender_record['signing_public_key']
        sender_spriv = sender_record['encrypted_signing_private_key']
        
        if not sender_spub or not sender_spriv:
            sender_spub, sender_spriv = generate_signing_keypair(session['passphrase'])
            db.execute(
                "UPDATE Users SET signing_public_key = ?, encrypted_signing_private_key = ? WHERE id = ?",
                (sender_spub, sender_spriv, session['user_id'])
            )
            db.commit()
            session['signing_public_key'] = sender_spub
            
        sig_b64, sig_time_ms = sign_file_hash(file_hash, sender_spriv, session['passphrase'])
        
        # Secure the filename & write ciphertext to storage
        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}.enc"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        current_utc = utc_now_str()
        
        # Insert File record
        cur = db.cursor()
        cur.execute(
            '''INSERT INTO Files (timestamp, filename, sender_id, receiver_id, encrypted_path, 
                                  encrypted_aes_key, iv, hmac_hash, file_hash, 
                                  hash_algorithm, hash_time_ms, file_size_bytes) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (current_utc, filename, session['user_id'], receiver_id, file_path, 
             encrypted_aes_key, iv, hmac_hash, file_hash, 
             'SHA-256', hash_time_ms, file_size_bytes)
        )
        new_file_id = cur.lastrowid
        
        # Insert Digital Signature record
        cur.execute(
            '''INSERT INTO DigitalSignatures (timestamp, user_id, message, signature, public_key, algorithm, verified, file_id, signing_time_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (current_utc, session['user_id'], file_hash, sig_b64, sender_spub, 'RSA-PSS-SHA256', 0, new_file_id, sig_time_ms)
        )
        new_sig_id = cur.lastrowid
        
        # Link signature_id to Files
        cur.execute('UPDATE Files SET signature_id = ? WHERE id = ?', (new_sig_id, new_file_id))
        db.commit()
        db.close()
        
        total_upload_duration_ms = (time.perf_counter() - t_upload_start) * 1000.0
        crypto_total_ms = (
            enc_timings.get('enc_time_ms', 0) + 
            enc_timings.get('key_wrap_time_ms', 0) + 
            enc_timings.get('hmac_time_ms', 0) + 
            hash_time_ms + 
            sig_time_ms
        )
        
        # Granular upload performance timing breakdown
        upload_timings = {
            'enc_time_ms': enc_timings.get('enc_time_ms'),
            'key_wrap_time_ms': enc_timings.get('key_wrap_time_ms'),
            'hmac_time_ms': enc_timings.get('hmac_time_ms'),
            'hash_time_ms': hash_time_ms,
            'sig_time_ms': sig_time_ms
        }
        
        # Record real performance metrics persistently
        live_collector.record_performance(
            operation_type="UPLOAD",
            file_size_bytes=file_size_bytes,
            crypto_duration_ms=crypto_total_ms,
            total_duration_ms=total_upload_duration_ms,
            status="SUCCESS",
            details=f"Uploaded {filename} ({file_size_bytes} B)",
            file_id=new_file_id,
            timings=upload_timings
        )
        
        log_event(session['user_id'], "FILE_UPLOAD", "SUCCESS", f"Uploaded encrypted and signed {filename} to receiver {receiver_id}")
        
        # Provide upload processing summary in session for GUI display
        session['last_upload_summary'] = {
            'filename': filename,
            'file_size_bytes': file_size_bytes,
            'receiver_id': receiver_id,
            'file_hash': file_hash,
            'signature_id': new_sig_id,
            'enc_time_ms': round(enc_timings.get('enc_time_ms', 0), 2),
            'key_wrap_time_ms': round(enc_timings.get('key_wrap_time_ms', 0), 2),
            'hmac_time_ms': round(enc_timings.get('hmac_time_ms', 0), 2),
            'hash_time_ms': round(hash_time_ms, 2),
            'sig_time_ms': round(sig_time_ms, 2),
            'total_crypto_ms': round(crypto_total_ms, 2)
        }
        flash('File encrypted, hashed, signed, and sent successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Fetch all users except the currently logged in user
    users = db.execute(
        'SELECT id, username FROM Users WHERE id != ?', (session['user_id'],)
    ).fetchall()
    db.close()
    
    upload_summary = session.pop('last_upload_summary', None)
    return render_template('dashboard.html', username=session['username'], users=users, upload_summary=upload_summary)


@app.route('/inbox')
@login_required
def inbox():
    db = get_db_connection()
    # Fetch files where the logged-in user is the receiver along with sender information and signatures
    files = db.execute(
        '''SELECT Files.*, 
                  Users.username as sender_name,
                  Users.signing_public_key as sender_signing_public_key,
                  Users.public_key as sender_encryption_public_key,
                  DigitalSignatures.signature as signature_b64,
                  DigitalSignatures.signing_time_ms,
                  DigitalSignatures.timestamp as signature_timestamp
           FROM Files 
           JOIN Users ON Files.sender_id = Users.id 
           LEFT JOIN DigitalSignatures ON Files.signature_id = DigitalSignatures.id
           WHERE Files.receiver_id = ? 
           ORDER BY Files.timestamp DESC''', 
        (session['user_id'],)
    ).fetchall()
    db.close()
    return render_template('inbox.html', files=files)


@app.route('/download/package/<int:file_id>')
@login_required
def download_encrypted_package(file_id):
    """
    OPTION A: Download Portable Secure Encrypted Package (.cspkg)
    Allows authorized receiver to download the encrypted package without decrypting it.
    Contains: payload.enc, metadata.json (wrapped AES key, IV, HMAC, SHA-256 digest, RSA-PSS signature, public keys)
    """
    t_start = time.perf_counter()
    db = get_db_connection()
    file_record = db.execute(
        '''SELECT Files.*, DigitalSignatures.signature as signature_b64
           FROM Files 
           LEFT JOIN DigitalSignatures ON Files.signature_id = DigitalSignatures.id 
           WHERE Files.id = ?''', (file_id,)
    ).fetchone()
    
    if file_record is None:
        db.close()
        flash('File not found.', 'error')
        return redirect(url_for('inbox'))
        
    if file_record['receiver_id'] != session['user_id']:
        db.close()
        security_manager.record_unauthorized_access(
            get_client_ip(), session['user_id'], f"Attempted to download package file_id {file_id}"
        )
        flash('Unauthorized: You do not have permission to access this file.', 'error')
        return redirect(url_for('inbox'))
        
    file_path = file_record['encrypted_path']
    if not os.path.exists(file_path):
        db.close()
        flash('File missing on server.', 'error')
        return redirect(url_for('inbox'))
        
    sender_record = db.execute('SELECT * FROM Users WHERE id = ?', (file_record['sender_id'],)).fetchone()
    receiver_record = db.execute('SELECT * FROM Users WHERE id = ?', (session['user_id'],)).fetchone()
    db.close()
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
        
    from core.crypto import create_encrypted_package
    pkg_bytes = create_encrypted_package(file_record, sender_record, receiver_record, encrypted_data)
    
    log_event(session['user_id'], "PACKAGE_DOWNLOAD", "SUCCESS", f"Downloaded encrypted package for file_id {file_id}")
    import io
    return send_file(
        io.BytesIO(pkg_bytes),
        as_attachment=True,
        download_name=f"{os.path.splitext(file_record['filename'])[0]}.cspkg",
        mimetype="application/octet-stream"
    )


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """
    OPTION B: Verify, Decrypt and Download
    1. Authenticates session and receiver authorization.
    2. Verifies HMAC-SHA256 integrity of encrypted payload.
    3. Unwraps AES-256 key using receiver's RSA private key.
    4. Decrypts original file.
    5. Calculates fresh SHA-256 digest of decrypted file and compares with stored original digest.
    6. Verifies sender's RSA-PSS digital signature using sender's public key.
    7. Only sends decrypted file if all mandatory verification checks pass.
    """
    t_download_start = time.perf_counter()
    db = get_db_connection()
    file_record = db.execute(
        '''SELECT Files.*, DigitalSignatures.signature as signature_b64
           FROM Files 
           LEFT JOIN DigitalSignatures ON Files.signature_id = DigitalSignatures.id 
           WHERE Files.id = ?''', (file_id,)
    ).fetchone()
    
    if file_record is None:
        db.close()
        live_collector.record_performance(
            operation_type="DOWNLOAD",
            file_size_bytes=0,
            total_duration_ms=(time.perf_counter() - t_download_start) * 1000.0,
            status="NOT_FOUND",
            details=f"File {file_id} not found"
        )
        flash('File not found.', 'error')
        return redirect(url_for('inbox'))
        
    # RECEIVER ISOLATION / AUTHORIZATION CHECK
    if file_record['receiver_id'] != session['user_id']:
        db.close()
        security_manager.record_unauthorized_access(
            get_client_ip(),
            session['user_id'],
            f"Attempted to access file_id {file_id}"
        )
        live_collector.record_performance(
            operation_type="DOWNLOAD",
            file_size_bytes=0,
            total_duration_ms=(time.perf_counter() - t_download_start) * 1000.0,
            status="UNAUTHORIZED",
            details=f"Unauthorized access to file {file_id}"
        )
        flash('Unauthorized: You do not have permission to access this file.', 'error')
        return redirect(url_for('inbox'))
        
    file_path = file_record['encrypted_path']
    if not os.path.exists(file_path):
        db.close()
        live_collector.record_performance(
            operation_type="DOWNLOAD",
            file_size_bytes=0,
            total_duration_ms=(time.perf_counter() - t_download_start) * 1000.0,
            status="FILE_MISSING",
            details=f"Encrypted file missing on disk: {file_id}"
        )
        flash('File missing on server.', 'error')
        return redirect(url_for('inbox'))
        
    # Fetch receiver and sender records
    user_record = db.execute('SELECT encrypted_private_key FROM Users WHERE id = ?', (session['user_id'],)).fetchone()
    sender_record = db.execute('SELECT * FROM Users WHERE id = ?', (file_record['sender_id'],)).fetchone()
    db.close()
    
    if not user_record or not user_record['encrypted_private_key']:
        live_collector.record_performance(
            operation_type="DOWNLOAD",
            file_size_bytes=0,
            total_duration_ms=(time.perf_counter() - t_download_start) * 1000.0,
            status="KEY_ERROR",
            details="Receiver private key missing"
        )
        flash('Cryptographic error: Private key missing.', 'error')
        return redirect(url_for('inbox'))
        
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        from core.crypto import (
            decrypt_file_data, 
            compute_file_sha256, 
            verify_file_hash_signature
        )
        
        # 1. Decrypt file data & verify HMAC integrity
        decrypted_data, dec_timings = decrypt_file_data(
            encrypted_data,
            file_record['encrypted_aes_key'],
            file_record['iv'],
            file_record['hmac_hash'],
            user_record['encrypted_private_key'],
            session['passphrase'],
            return_timings=True
        )
        
        # 2. Re-compute SHA-256 on recovered plaintext
        recovered_hash, hash_verify_ms = compute_file_sha256(decrypted_data)
        dec_timings['hash_verify_time_ms'] = hash_verify_ms
        
        # 3. Check SHA-256 match if original hash was recorded
        if file_record['file_hash']:
            if recovered_hash != file_record['file_hash']:
                log_event(session['user_id'], "HASH_MISMATCH", "FAILURE", f"SHA-256 digest mismatch for file {file_id}")
                flash('Security Error: SHA-256 digest mismatch. Decrypted file content does not match original.', 'error')
                return redirect(url_for('inbox'))
                
        # 4. Verify Digital Signature if available
        sig_verify_ms = 0.0
        if file_record['signature_b64'] and sender_record and sender_record['signing_public_key']:
            sig_valid, sig_verify_ms, sig_err = verify_file_hash_signature(
                file_record['file_hash'],
                file_record['signature_b64'],
                sender_record['signing_public_key']
            )
            dec_timings['sig_verify_time_ms'] = sig_verify_ms
            if not sig_valid:
                log_event(session['user_id'], "SIGNATURE_VERIFICATION_FAILED", "FAILURE", f"Invalid RSA-PSS signature on file {file_id}: {sig_err}")
                flash('Security Error: Digital signature verification failed. Sender cannot be authenticated.', 'error')
                return redirect(url_for('inbox'))
        
        file_size_bytes = len(decrypted_data)
        total_download_duration_ms = (time.perf_counter() - t_download_start) * 1000.0
        crypto_total_ms = (
            dec_timings.get('key_unwrap_time_ms', 0) + 
            dec_timings.get('hmac_verify_time_ms', 0) + 
            dec_timings.get('dec_time_ms', 0) + 
            hash_verify_ms + 
            sig_verify_ms
        )
        
        # Record successful download performance
        live_collector.record_performance(
            operation_type="DOWNLOAD",
            file_size_bytes=file_size_bytes,
            crypto_duration_ms=crypto_total_ms,
            total_duration_ms=total_download_duration_ms,
            status="SUCCESS",
            details=f"Downloaded {file_record['filename']} ({file_size_bytes} B)",
            file_id=file_id,
            timings=dec_timings
        )
        
        log_event(session['user_id'], "FILE_DOWNLOAD", "SUCCESS", f"Verified, decrypted, and accessed file_id {file_id}")
        
        import io
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file_record['filename']
        )
    except ValueError as e:
        total_download_duration_ms = (time.perf_counter() - t_download_start) * 1000.0
        if str(e) == "INTEGRITY_CHECK_FAILED":
            live_collector.record_performance(
                operation_type="DOWNLOAD",
                file_size_bytes=0,
                total_duration_ms=total_download_duration_ms,
                status="INTEGRITY_FAILED",
                details="HMAC integrity check failed"
            )
            log_event(session['user_id'], "INTEGRITY_CHECK_FAILED", "FAILURE", f"Integrity check failed for file {file_id}")
            flash('Error: File integrity check failed. The file may have been tampered with.', 'error')
        else:
            live_collector.record_performance(
                operation_type="DOWNLOAD",
                file_size_bytes=0,
                total_duration_ms=total_download_duration_ms,
                status="DECRYPTION_ERROR",
                details=str(e)
            )
            log_event(session['user_id'], "DECRYPTION_ERROR", "FAILURE", f"Failed to decrypt file {file_id}: {str(e)}")
            flash('Error decrypting file. Keys may be invalid.', 'error')
        return redirect(url_for('inbox'))
    except Exception as e:
        total_download_duration_ms = (time.perf_counter() - t_download_start) * 1000.0
        live_collector.record_performance(
            operation_type="DOWNLOAD",
            file_size_bytes=0,
            total_duration_ms=total_download_duration_ms,
            status="DECRYPTION_ERROR",
            details=str(e)
        )
        log_event(session['user_id'], "DECRYPTION_ERROR", "FAILURE", f"Failed to decrypt file {file_id}")
        flash('Error decrypting file. The file may be corrupted or keys may be invalid.', 'error')
        return redirect(url_for('inbox'))


@app.route('/security-monitor')
@login_required
def security_monitor():
    """
    Phase 10: Security Monitoring and Audit Logs Dashboard.
    Protected view accessible only by authenticated sessions on loopback/local admin or with monitor key.
    """
    if not can_access_security_monitor(request):
        log_event(
            session.get('user_id'),
            "UNAUTHORIZED_ACCESS",
            "FAILURE",
            "Unauthorized attempt to access Security Monitoring dashboard"
        )
        flash('Access Denied: Security Monitor is restricted to authorized administrative/local sessions.', 'error')
        return redirect(url_for('dashboard'))
        
    db = get_db_connection()
    
    # Event filter
    filter_category = request.args.get('filter', 'all')
    query = '''
        SELECT AuditLogs.id, AuditLogs.timestamp, AuditLogs.event_type, AuditLogs.status, 
               AuditLogs.description, AuditLogs.ip_address, AuditLogs.user_id, Users.username
        FROM AuditLogs
        LEFT JOIN Users ON AuditLogs.user_id = Users.id
    '''
    params = []
    
    if filter_category == 'ids':
        query += " WHERE AuditLogs.event_type IN ('IDS_SUSPICIOUS_ACTIVITY', 'UNAUTHORIZED_ACCESS', 'INTEGRITY_CHECK_FAILED')"
    elif filter_category == 'rate_limit':
        query += " WHERE AuditLogs.event_type IN ('RATE_LIMIT_EXCEEDED', 'LOGIN_RATE_LIMITED')"
    elif filter_category == 'auth':
        query += " WHERE AuditLogs.event_type IN ('LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGIN_RATE_LIMITED', 'REGISTER', 'LOGOUT')"
    elif filter_category == 'files':
        query += " WHERE AuditLogs.event_type IN ('FILE_UPLOAD', 'FILE_DOWNLOAD', 'INTEGRITY_CHECK_FAILED', 'UNAUTHORIZED_ACCESS')"

    query += " ORDER BY AuditLogs.id DESC LIMIT 100"
    logs = db.execute(query, params).fetchall()

    # Calculate summary metrics
    total_events = db.execute("SELECT COUNT(*) as count FROM AuditLogs").fetchone()['count']
    ids_alerts = db.execute("SELECT COUNT(*) as count FROM AuditLogs WHERE event_type = 'IDS_SUSPICIOUS_ACTIVITY'").fetchone()['count']
    rate_limits = db.execute("SELECT COUNT(*) as count FROM AuditLogs WHERE event_type IN ('RATE_LIMIT_EXCEEDED', 'LOGIN_RATE_LIMITED')").fetchone()['count']
    failed_logins = db.execute("SELECT COUNT(*) as count FROM AuditLogs WHERE event_type = 'LOGIN_FAILURE'").fetchone()['count']
    integrity_failures = db.execute("SELECT COUNT(*) as count FROM AuditLogs WHERE event_type = 'INTEGRITY_CHECK_FAILED'").fetchone()['count']
    unauth_events = db.execute("SELECT COUNT(*) as count FROM AuditLogs WHERE event_type = 'UNAUTHORIZED_ACCESS'").fetchone()['count']
    
    db.close()

    # Active cooldowns from memory
    client_ip = get_client_ip()
    is_cooldown, remaining = security_manager.check_login_cooldown(client_ip)

    return render_template(
        'security_monitor.html',
        logs=logs,
        filter_category=filter_category,
        total_events=total_events,
        ids_alerts=ids_alerts,
        rate_limits=rate_limits,
        failed_logins=failed_logins,
        integrity_failures=integrity_failures,
        unauth_events=unauth_events,
        is_cooldown=is_cooldown,
        cooldown_remaining=remaining
    )


if __name__ == '__main__':
    import socket

    def get_lan_ip():
        """Attempts to discover the primary outbound LAN IPv4 address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to an external address (doesn't send actual packets) to determine routing interface
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    lan_ip = get_lan_ip()
    host = app.config.get('HOST', '0.0.0.0')
    port = app.config.get('PORT', 5000)

    print("=" * 65)
    print(" CipherShare Secure File Transfer - Server Initialized")
    print("=" * 65)
    print(f" Localhost Access (Device A):       http://localhost:{port}")
    if host == '0.0.0.0':
        print(f" LAN Access (Device B / Mobile):    http://{lan_ip}:{port}")
    else:
        print(f" Custom Host Binding:               http://{host}:{port}")
    print("=" * 65)
    print(f" Listening on {host}:{port} ... Press CTRL+C to quit.\n")

    app.run(host=host, port=port, debug=False)
