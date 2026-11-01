"""
CipherShare — Routes Blueprint
All new module pages and API endpoints for cryptographic operations.
"""

from flask import Blueprint, request, jsonify, render_template, session
from core.auth import login_required
from database.models import get_db_connection
from core.time_utils import utc_now_str, format_ist
import base64
import traceback

crypto_bp = Blueprint('crypto', __name__)


# =====================================================================
# PAGE ROUTES (render templates)
# =====================================================================

@crypto_bp.route('/overview')
@login_required
def overview():
    db = get_db_connection()
    stats = {
        'total_users': db.execute('SELECT COUNT(*) as c FROM Users').fetchone()['c'],
        'total_files': db.execute('SELECT COUNT(*) as c FROM Files').fetchone()['c'],
        'total_uploads': db.execute("SELECT COUNT(*) as c FROM AuditLogs WHERE event_type='FILE_UPLOAD' AND status='SUCCESS'").fetchone()['c'],
        'failed_logins': db.execute("SELECT COUNT(*) as c FROM AuditLogs WHERE event_type='LOGIN_FAILURE'").fetchone()['c'],
        'integrity_ok': db.execute("SELECT COUNT(*) as c FROM AuditLogs WHERE event_type='INTEGRITY_CHECK_FAILED'").fetchone()['c'] == 0,
        'total_events': db.execute('SELECT COUNT(*) as c FROM AuditLogs').fetchone()['c'],
        'total_signatures': db.execute('SELECT COUNT(*) as c FROM DigitalSignatures').fetchone()['c'],
    }
    recent = db.execute(
        "SELECT AuditLogs.*, Users.username FROM AuditLogs LEFT JOIN Users ON AuditLogs.user_id=Users.id ORDER BY AuditLogs.id DESC LIMIT 10"
    ).fetchall()
    db.close()
    return render_template('overview.html', active_page='overview', stats=stats, recent=recent)


@crypto_bp.route('/text-encryption')
@login_required
def text_encryption_page():
    return render_template('text_encryption.html', active_page='text_encryption')


@crypto_bp.route('/image-encryption')
@login_required
def image_encryption_page():
    return render_template('image_encryption.html', active_page='image_encryption')


@crypto_bp.route('/security-analysis')
@login_required
def security_analysis_page():
    return render_template('security_analysis.html', active_page='security_analysis')


@crypto_bp.route('/performance')
@login_required
def performance_page():
    return render_template('performance.html', active_page='performance')


@crypto_bp.route('/hashing')
@login_required
def hashing_page():
    return render_template('hashing.html', active_page='hashing')


@crypto_bp.route('/digital-signatures')
@login_required
def digital_signatures_page():
    db = get_db_connection()
    sigs = db.execute(
        "SELECT id, timestamp, message, algorithm FROM DigitalSignatures WHERE user_id=? ORDER BY id DESC LIMIT 20",
        (session['user_id'],)
    ).fetchall()
    db.close()
    return render_template('digital_signatures.html', active_page='digital_signatures', signatures=sigs)


@crypto_bp.route('/traffic')
@login_required
def traffic_page():
    db = get_db_connection()
    events = db.execute(
        "SELECT * FROM TrafficActivity ORDER BY id DESC LIMIT 100"
    ).fetchall()
    cat_counts = {}
    rows = db.execute("SELECT event_category, COUNT(*) as c FROM TrafficActivity GROUP BY event_category").fetchall()
    for r in rows:
        cat_counts[r['event_category']] = r['c']
    total_bytes = db.execute("SELECT COALESCE(SUM(payload_size_bytes),0) as s FROM TrafficActivity").fetchone()['s']
    db.close()
    return render_template('traffic_analysis.html', active_page='traffic', events=events, cat_counts=cat_counts, total_bytes=total_bytes)


# =====================================================================
# API: TEXT ENCRYPTION
# =====================================================================

@crypto_bp.route('/api/text/encrypt', methods=['POST'])
@login_required
def api_text_encrypt():
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        if not plaintext:
            return jsonify({'error': 'Plaintext is required'}), 400
        from core.crypto_utils import encrypt_text
        result = encrypt_text(plaintext)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/text/decrypt', methods=['POST'])
@login_required
def api_text_decrypt():
    try:
        data = request.get_json()
        ct = data.get('ciphertext_b64', '')
        key = data.get('key_b64', '')
        iv = data.get('iv_b64', '')
        if not ct or not key or not iv:
            return jsonify({'error': 'Ciphertext, key and IV are required'}), 400
        from core.crypto_utils import decrypt_text
        result = decrypt_text(ct, key, iv)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API: IMAGE ENCRYPTION
# =====================================================================

@crypto_bp.route('/api/image/encrypt', methods=['POST'])
@login_required
def api_image_encrypt():
    try:
        f = request.files.get('image')
        if not f or f.filename == '':
            return jsonify({'error': 'Image file is required'}), 400
        allowed = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
        ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
        if ext not in allowed:
            return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed)}'}), 400
        image_bytes = f.read()
        if len(image_bytes) > 10 * 1024 * 1024:
            return jsonify({'error': 'Image too large (max 10 MB)'}), 400
        from core.crypto_utils import encrypt_image
        result = encrypt_image(image_bytes)
        result['original_b64'] = base64.b64encode(image_bytes).decode()
        result['filename'] = f.filename
        result['content_type'] = f.content_type or 'image/png'
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/image/decrypt', methods=['POST'])
@login_required
def api_image_decrypt():
    try:
        data = request.get_json()
        ct = data.get('ciphertext_b64', '')
        key = data.get('key_b64', '')
        iv = data.get('iv_b64', '')
        if not ct or not key or not iv:
            return jsonify({'error': 'Ciphertext, key and IV are required'}), 400
        from core.crypto_utils import decrypt_image
        result = decrypt_image(ct, key, iv)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API: SECURITY ANALYSIS
# =====================================================================

@crypto_bp.route('/api/analysis/confusion', methods=['POST'])
@login_required
def api_confusion():
    try:
        data = request.get_json() or {}
        pt = data.get('plaintext', None)
        from core.crypto_utils import analyze_confusion
        return jsonify(analyze_confusion(pt))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/analysis/diffusion', methods=['POST'])
@login_required
def api_diffusion():
    try:
        data = request.get_json() or {}
        pt = data.get('plaintext', None)
        from core.crypto_utils import analyze_diffusion
        return jsonify(analyze_diffusion(pt))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/analysis/avalanche', methods=['POST'])
@login_required
def api_avalanche():
    try:
        from core.crypto_utils import analyze_avalanche
        return jsonify(analyze_avalanche())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API: HASHING
# =====================================================================

@crypto_bp.route('/api/hash/generate', methods=['POST'])
@login_required
def api_hash_generate():
    try:
        data = request.get_json()
        text = data.get('text', '')
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        from core.crypto_utils import generate_sha256
        return jsonify(generate_sha256(text))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/hash/preimage', methods=['POST'])
@login_required
def api_hash_preimage():
    try:
        data = request.get_json()
        prefix = data.get('prefix', '')
        if not prefix:
            return jsonify({'error': 'Target prefix is required'}), 400
        from core.crypto_utils import demo_preimage
        return jsonify(demo_preimage(prefix))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/hash/second-preimage', methods=['POST'])
@login_required
def api_hash_second_preimage():
    try:
        data = request.get_json()
        msg = data.get('message', '')
        if not msg:
            return jsonify({'error': 'Original message is required'}), 400
        from core.crypto_utils import demo_second_preimage
        return jsonify(demo_second_preimage(msg))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/hash/collision', methods=['POST'])
@login_required
def api_hash_collision():
    try:
        data = request.get_json() or {}
        bits = data.get('bits', 16)
        from core.crypto_utils import demo_collision
        return jsonify(demo_collision(int(bits)))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API: DIGITAL SIGNATURES (RSA-PSS)
# =====================================================================

@crypto_bp.route('/api/signature/generate', methods=['POST'])
@login_required
def api_signature_generate():
    try:
        data = request.get_json()
        message = data.get('message', '')
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        from core.crypto_utils import generate_signing_keypair, sign_message
        # Generate or reuse session signing keys
        if 'signing_private_key' not in session:
            pub, priv = generate_signing_keypair()
            session['signing_public_key'] = pub
            session['signing_private_key'] = priv
        result = sign_message(message, session['signing_private_key'])
        current_utc = utc_now_str()
        # Store in database
        db = get_db_connection()
        db.execute(
            "INSERT INTO DigitalSignatures (timestamp, user_id, message, signature, public_key, algorithm) VALUES (?,?,?,?,?,?)",
            (current_utc, session['user_id'], message, result['signature_b64'], session['signing_public_key'], 'RSA-PSS-SHA256')
        )
        db.commit()
        db.close()
        result['public_key'] = session['signing_public_key']
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/signature/verify', methods=['POST'])
@login_required
def api_signature_verify():
    try:
        data = request.get_json()
        message = data.get('message', '')
        sig_b64 = data.get('signature_b64', '')
        pub_key = data.get('public_key', '')
        sig_id = data.get('signature_id', None)

        # If signature_id provided, load from database
        if sig_id and (not sig_b64 or not pub_key):
            db = get_db_connection()
            rec = db.execute("SELECT * FROM DigitalSignatures WHERE id=?", (sig_id,)).fetchone()
            db.close()
            if not rec:
                return jsonify({'error': 'Signature not found'}), 404
            if not sig_b64:
                sig_b64 = rec['signature']
            if not pub_key:
                pub_key = rec['public_key']
            if not message:
                message = rec['message']

        if not message or not sig_b64 or not pub_key:
            return jsonify({'error': 'Message, signature and public key are required'}), 400

        from core.crypto_utils import verify_signature
        result = verify_signature(message, sig_b64, pub_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/signature/list', methods=['GET'])
@login_required
def api_signature_list():
    db = get_db_connection()
    sigs = db.execute(
        "SELECT id, timestamp, message, signature, public_key, algorithm FROM DigitalSignatures WHERE user_id=? ORDER BY id DESC",
        (session['user_id'],)
    ).fetchall()
    db.close()
    return jsonify([dict(s) for s in sigs])


# =====================================================================
# API: PERFORMANCE BENCHMARKS
# =====================================================================

@crypto_bp.route('/api/performance/run', methods=['POST'])
@login_required
def api_performance_run():
    try:
        from core.crypto_utils import run_text_benchmark, run_image_benchmark
        text_results = run_text_benchmark()
        image_results = run_image_benchmark()
        return jsonify({'text': text_results, 'image': image_results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API: FILE SHARING CRYPTO DETAILS & VERIFICATION
# =====================================================================

@crypto_bp.route('/api/file/verify-signature', methods=['POST'])
@login_required
def api_file_verify_signature():
    """Verifies the RSA-PSS digital signature of a specific shared file using sender's trusted public key."""
    try:
        data = request.get_json() or {}
        file_id = data.get('file_id')
        if not file_id:
            return jsonify({'error': 'file_id is required'}), 400

        db = get_db_connection()
        file_rec = db.execute(
            '''SELECT Files.*, 
                      Users.username as sender_name,
                      Users.signing_public_key as sender_signing_public_key,
                      DigitalSignatures.signature as signature_b64,
                      DigitalSignatures.timestamp as sig_timestamp
               FROM Files
               JOIN Users ON Files.sender_id = Users.id
               LEFT JOIN DigitalSignatures ON Files.signature_id = DigitalSignatures.id
               WHERE Files.id = ?''', (file_id,)
        ).fetchone()
        db.close()

        if not file_rec:
            return jsonify({'error': 'File not found'}), 404

        # Check authorization: user must be sender or receiver
        if file_rec['receiver_id'] != session['user_id'] and file_rec['sender_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403

        if not file_rec['file_hash']:
            return jsonify({'error': 'File does not have a recorded SHA-256 hash'}), 400

        if not file_rec['signature_b64'] or not file_rec['sender_signing_public_key']:
            return jsonify({'error': 'File does not have a digital signature'}), 400

        from core.crypto import verify_file_hash_signature
        valid, ver_ms, err = verify_file_hash_signature(
            file_rec['file_hash'],
            file_rec['signature_b64'],
            file_rec['sender_signing_public_key']
        )

        return jsonify({
            'valid': valid,
            'verification_time_ms': round(ver_ms, 3),
            'file_id': file_id,
            'filename': file_rec['filename'],
            'file_hash': file_rec['file_hash'],
            'sender_name': file_rec['sender_name'],
            'signature_b64': file_rec['signature_b64'],
            'algorithm': 'RSA-PSS-SHA256',
            'error': err if not valid else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/file/details/<int:file_id>', methods=['GET'])
@login_required
def api_file_details(file_id):
    """Returns complete cryptographic and integrity metadata for a given shared file.
    Handles both legacy files (no file_hash / signature_id) and newly uploaded files
    that include SHA-256 digest, RSA-PSS signature, and performance metrics.
    """
    try:
        db = get_db_connection()
        f = db.execute(
            '''SELECT Files.*,
                      sender.username  AS sender_name,
                      receiver.username AS receiver_name,
                      sender.signing_public_key AS sender_signing_public_key,
                      DigitalSignatures.signature    AS signature_b64,
                      DigitalSignatures.signing_time_ms,
                      DigitalSignatures.timestamp    AS sig_timestamp
               FROM Files
               LEFT JOIN Users AS sender   ON Files.sender_id   = sender.id
               LEFT JOIN Users AS receiver ON Files.receiver_id = receiver.id
               LEFT JOIN DigitalSignatures ON Files.signature_id = DigitalSignatures.id
               WHERE Files.id = ?''', (file_id,)
        ).fetchone()
        db.close()

        if not f:
            return jsonify({'error': 'File not found'}), 404

        if f['receiver_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403

        return jsonify({
            # Identity
            'id': f['id'],
            'filename': f['filename'],
            'sender_name': f['sender_name'],
            'receiver_name': f['receiver_name'],
            'file_size_bytes': f['file_size_bytes'],
            'timestamp': f['timestamp'],
            'timestamp_ist': format_ist(f['timestamp']) if f['timestamp'] else None,
            # Algorithms — always populated (these don't change across legacy/new)
            'encryption_algorithm': 'AES-256-CBC',
            'key_protection': 'RSA-2048-OAEP',
            'integrity_algorithm': 'HMAC-SHA256',
            # File hash — None for legacy files, hex string for new files
            'file_hash': f['file_hash'],
            'hash_algorithm': f['hash_algorithm'] or 'SHA-256',
            'hash_time_ms': f['hash_time_ms'],
            # HMAC presence — True for all files (hmac_hash always stored),
            # but null hash means the HMAC key was derived differently pre-migration
            'hmac_available': bool(f['hmac_hash']),
            # Signature — None for legacy files
            'signature_b64': f['signature_b64'],
            'signature_algorithm': 'RSA-PSS-SHA256' if f['signature_b64'] else None,
            'signing_time_ms': f['signing_time_ms'],
            'signature_timestamp': f['sig_timestamp'],
            'signature_timestamp_ist': format_ist(f['sig_timestamp']) if f['sig_timestamp'] else None,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_bp.route('/api/performance/file-sharing', methods=['GET'])
@login_required
def api_file_sharing_performance():
    """Returns actual aggregated performance metrics for file sharing operations."""
    try:
        db = get_db_connection()
        rows = db.execute(
            '''SELECT id, operation_type, file_size_bytes, crypto_duration_ms, total_duration_ms,
                      enc_time_ms, key_wrap_time_ms, hmac_time_ms, hash_time_ms, sig_time_ms,
                      dec_time_ms, key_unwrap_time_ms, hmac_verify_time_ms, hash_verify_time_ms, sig_verify_time_ms,
                      timestamp, details
               FROM PerformanceMetrics 
               WHERE operation_type IN ('UPLOAD', 'DOWNLOAD') AND status='SUCCESS'
               ORDER BY id DESC LIMIT 50'''
        ).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
