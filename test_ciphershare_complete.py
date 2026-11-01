"""
CipherShare — Comprehensive functional test for all new modules.
Tests crypto_utils, routes imports, and database migration.
"""
import sys
import base64
import hashlib

sys.path.insert(0, '.')


def test_text_encryption():
    from core.crypto_utils import encrypt_text, decrypt_text
    pt = "Hello CipherShare! This is a test message."
    enc = encrypt_text(pt)
    assert enc['plaintext'] == pt
    assert enc['ciphertext_b64']
    assert enc['key_b64']
    assert enc['iv_b64']
    assert enc['algorithm'] == 'AES-256-CBC'
    assert enc['encryption_time_ms'] > 0
    assert enc['ciphertext_size'] > 0

    dec = decrypt_text(enc['ciphertext_b64'], enc['key_b64'], enc['iv_b64'])
    assert dec['plaintext'] == pt, f"Decryption mismatch: {dec['plaintext']!r} != {pt!r}"
    assert dec['decryption_time_ms'] > 0
    print(f"  [PASS] Text encryption/decryption — enc:{enc['encryption_time_ms']}ms dec:{dec['decryption_time_ms']}ms")


def test_image_encryption():
    import os
    from core.crypto_utils import encrypt_image, decrypt_image
    img_bytes = os.urandom(1024 * 50)  # 50 KB dummy image bytes
    enc = encrypt_image(img_bytes)
    assert enc['ciphertext_b64']
    assert enc['original_size'] == len(img_bytes)
    assert enc['encryption_time_ms'] > 0

    dec = decrypt_image(enc['ciphertext_b64'], enc['key_b64'], enc['iv_b64'])
    recovered = base64.b64decode(dec['image_b64'])
    assert recovered == img_bytes, "Image bytes do not match after decrypt!"
    assert dec['decryption_time_ms'] > 0
    print(f"  [PASS] Image encryption/decryption — enc:{enc['encryption_time_ms']}ms dec:{dec['decryption_time_ms']}ms")


def test_confusion():
    from core.crypto_utils import analyze_confusion
    r = analyze_confusion("Test plaintext for confusion analysis.")
    assert 0 <= r['bit_change_percentage'] <= 100
    assert r['changed_bits'] <= r['total_bits']
    assert r['ciphertext1_hex'] != r['ciphertext2_hex']
    print(f"  [PASS] Confusion — {r['bit_change_percentage']}% bit change ({r['changed_bits']}/{r['total_bits']} bits)")


def test_diffusion():
    from core.crypto_utils import analyze_diffusion
    r = analyze_diffusion("Test plaintext for diffusion analysis.")
    assert 0 <= r['bit_change_percentage'] <= 100
    assert r['changed_bits'] <= r['total_bits']
    # 1-bit flip in CBC should propagate significantly
    assert r['changed_bits'] > 0
    print(f"  [PASS] Diffusion — {r['bit_change_percentage']}% bit change ({r['changed_bits']}/{r['total_bits']} bits)")


def test_avalanche():
    from core.crypto_utils import analyze_avalanche
    r = analyze_avalanche()
    pa = r['plaintext_avalanche']
    ka = r['key_avalanche']
    assert 0 <= pa['avalanche_percentage'] <= 100
    assert 0 <= ka['avalanche_percentage'] <= 100
    assert pa['changed_bits'] > 0
    assert ka['changed_bits'] > 0
    print(f"  [PASS] Avalanche — PT:{pa['avalanche_percentage']}% Key:{ka['avalanche_percentage']}%")


def test_sha256():
    from core.crypto_utils import generate_sha256
    msg = "CipherShare hash test"
    r = generate_sha256(msg)
    # Verify against stdlib
    expected = hashlib.sha256(msg.encode()).hexdigest()
    assert r['digest'] == expected, f"Hash mismatch: {r['digest']} != {expected}"
    assert r['digest_bits'] == 256
    assert r['generation_time_ms'] >= 0
    print(f"  [PASS] SHA-256 — {r['digest'][:16]}… ({r['generation_time_ms']}ms)")


def test_preimage():
    from core.crypto_utils import demo_preimage
    r = demo_preimage('a')  # 1 hex char prefix for fast demo
    assert r['attempts'] > 0
    assert r['time_ms'] > 0
    if r['found']:
        h = hashlib.sha256(r['found_input'].encode()).hexdigest()
        assert h[:1] == 'a', "Pre-image prefix doesn't match!"
    print(f"  [PASS] Pre-image resistance — {r['attempts']:,} attempts, found={r['found']}")


def test_second_preimage():
    from core.crypto_utils import demo_second_preimage
    r = demo_second_preimage("Hello World")
    assert r['attempts'] > 0
    assert r['original_hash']
    print(f"  [PASS] Second pre-image — {r['attempts']:,} attempts, found={r['found']}")


def test_collision():
    from core.crypto_utils import demo_collision
    r = demo_collision(16)  # 16-bit truncated hash — fast
    assert r['attempts'] > 0
    if r['found']:
        assert r['full_hashes_differ']  # Full SHA-256 must differ
        assert r['message1'] != r['message2']
    print(f"  [PASS] Collision resistance (16-bit) — {r['attempts']:,} attempts, found={r['found']}")


def test_digital_signatures():
    from core.crypto_utils import generate_signing_keypair, sign_message, verify_signature
    pub, priv = generate_signing_keypair()
    assert pub.startswith('-----BEGIN RSA PUBLIC KEY-----') or pub.startswith('-----BEGIN PUBLIC KEY-----')
    assert priv.startswith('-----BEGIN RSA PRIVATE KEY-----') or priv.startswith('-----BEGIN PRIVATE KEY-----')

    msg = "This document is signed by CipherShare."
    sig_result = sign_message(msg, priv)
    assert sig_result['signature_b64']
    assert sig_result['signature_size'] == 256  # RSA-2048 = 256 bytes
    assert sig_result['algorithm'] == 'RSA-PSS-SHA256'
    assert sig_result['signing_time_ms'] > 0

    # Valid verification
    vr = verify_signature(msg, sig_result['signature_b64'], pub)
    assert vr['valid'] is True, "Valid signature rejected!"
    assert vr['verification_time_ms'] > 0

    # Tampered message
    vr2 = verify_signature(msg + " TAMPERED", sig_result['signature_b64'], pub)
    assert vr2['valid'] is False, "Tampered message should fail verification!"

    print(f"  [PASS] Digital signatures — sign:{sig_result['signing_time_ms']}ms verify:{vr['verification_time_ms']}ms")
    print(f"  [PASS] Tamper detection — correctly rejected modified message")


def test_performance_benchmark():
    from core.crypto_utils import run_text_benchmark, run_image_benchmark
    text_results = run_text_benchmark(sizes=[1024, 10240], iterations=2)
    assert len(text_results) == 2
    for r in text_results:
        assert r['avg_enc_ms'] > 0
        assert r['avg_dec_ms'] > 0
        assert r['throughput_enc_kbs'] > 0
    print(f"  [PASS] Text benchmark — {len(text_results)} sizes, peak {max(r['throughput_enc_kbs'] for r in text_results):.0f} KB/s enc")

    img_results = run_image_benchmark(sizes=[1024, 10240], iterations=2)
    assert len(img_results) == 2
    print(f"  [PASS] Image benchmark — {len(img_results)} sizes, peak {max(r['throughput_enc_kbs'] for r in img_results):.0f} KB/s enc")


def test_routes_importable():
    from core.routes import crypto_bp
    from flask import Flask
    assert crypto_bp.name == 'crypto'
    # Register to a dummy app and verify routes exist
    dummy = Flask(__name__)
    dummy.register_blueprint(crypto_bp)
    route_names = [r.endpoint for r in dummy.url_map.iter_rules()]
    expected = ['crypto.overview','crypto.text_encryption_page','crypto.image_encryption_page',
                'crypto.security_analysis_page','crypto.hashing_page','crypto.digital_signatures_page',
                'crypto.performance_page','crypto.api_text_encrypt','crypto.api_signature_generate']
    for ep in expected:
        assert ep in route_names, f"Missing route: {ep}"
    print(f"  [PASS] Routes blueprint — {len(route_names)} routes registered")


def test_db_schema():
    from database.models import get_db_connection
    db = get_db_connection()
    # Check DigitalSignatures table exists
    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    table_names = [t['name'] for t in tables]
    assert 'DigitalSignatures' in table_names, f"DigitalSignatures table missing! Tables: {table_names}"
    assert 'Users' in table_names
    assert 'AuditLogs' in table_names
    assert 'Files' in table_names
    assert 'PerformanceMetrics' in table_names
    assert 'TrafficActivity' in table_names
    db.close()
    print(f"  [PASS] Database schema — tables: {', '.join(table_names)}")


def test_existing_crypto_module():
    """Ensure the original crypto.py still works (file-sharing pipeline)."""
    from core.crypto import generate_rsa_keypair, encrypt_file_data, decrypt_file_data
    password = 'TestPassword123!'
    pub_pem, priv_pem = generate_rsa_keypair(password)
    assert 'PUBLIC KEY' in pub_pem
    assert 'PRIVATE KEY' in priv_pem

    file_data = b"This is a test file for CipherShare file encryption."
    enc_data, enc_key_b64, iv_b64, hmac_b64 = encrypt_file_data(file_data, pub_pem)
    assert enc_key_b64
    assert iv_b64
    assert hmac_b64
    assert len(enc_data) > 0

    dec_data = decrypt_file_data(enc_data, enc_key_b64, iv_b64, hmac_b64, priv_pem, password)
    assert dec_data == file_data, f"File content mismatch: {dec_data!r}"
    print(f"  [PASS] Existing file encryption pipeline (AES-256-CBC + RSA-OAEP + HKDF + HMAC-SHA256)")


if __name__ == '__main__':
    tests = [
        ("Text Encryption & Decryption", test_text_encryption),
        ("Image Encryption & Decryption", test_image_encryption),
        ("Confusion Analysis", test_confusion),
        ("Diffusion Analysis", test_diffusion),
        ("Avalanche Effect", test_avalanche),
        ("SHA-256 Hashing", test_sha256),
        ("Pre-image Resistance Demo", test_preimage),
        ("Second Pre-image Demo", test_second_preimage),
        ("Collision Resistance Demo", test_collision),
        ("Digital Signatures (RSA-PSS)", test_digital_signatures),
        ("Performance Benchmarks", test_performance_benchmark),
        ("Routes Blueprint", test_routes_importable),
        ("Database Schema", test_db_schema),
        ("Existing File Crypto Pipeline", test_existing_crypto_module),
    ]

    passed = failed = 0
    print("\n" + "="*60)
    print(" CipherShare — Full Module Test Suite")
    print("="*60)
    for name, fn in tests:
        print(f"\n[TEST] {name}")
        try:
            fn()
            passed += 1
        except Exception as e:
            import traceback
            print(f"  [FAIL] {e}")
            traceback.print_exc()
            failed += 1

    print("\n" + "="*60)
    print(f" Results: {passed} PASSED  |  {failed} FAILED")
    print("="*60)
    sys.exit(0 if failed == 0 else 1)
