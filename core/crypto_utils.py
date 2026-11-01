"""
CipherShare Extended Cryptography Utilities
Text/Image encryption, security analysis, hashing, digital signatures, benchmarks.
All operations use actual AES-256-CBC / RSA-PSS / SHA-256 via pycryptodome.
"""

import base64
import time
import hashlib
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256


# =====================================================================
# TEXT ENCRYPTION / DECRYPTION (AES-256-CBC)
# =====================================================================

def encrypt_text(plaintext: str) -> dict:
    """Encrypt plaintext string using AES-256-CBC with a random key and IV."""
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    plaintext_bytes = plaintext.encode('utf-8')

    t0 = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    enc_ms = (time.perf_counter() - t0) * 1000

    return {
        'plaintext': plaintext,
        'ciphertext_b64': base64.b64encode(ciphertext).decode(),
        'ciphertext_hex': ciphertext.hex(),
        'key_b64': base64.b64encode(key).decode(),
        'iv_b64': base64.b64encode(iv).decode(),
        'algorithm': 'AES-256-CBC',
        'ciphertext_size': len(ciphertext),
        'plaintext_size': len(plaintext_bytes),
        'encryption_time_ms': round(enc_ms, 4),
    }


def decrypt_text(ciphertext_b64: str, key_b64: str, iv_b64: str) -> dict:
    """Decrypt AES-256-CBC ciphertext back to plaintext."""
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    t0 = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    dec_ms = (time.perf_counter() - t0) * 1000

    return {
        'plaintext': plaintext_bytes.decode('utf-8'),
        'decryption_time_ms': round(dec_ms, 4),
        'algorithm': 'AES-256-CBC',
    }


# =====================================================================
# IMAGE ENCRYPTION / DECRYPTION (AES-256-CBC)
# =====================================================================

def encrypt_image(image_bytes: bytes) -> dict:
    """Encrypt raw image bytes using AES-256-CBC."""
    key = get_random_bytes(32)
    iv = get_random_bytes(16)

    t0 = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(image_bytes, AES.block_size))
    enc_ms = (time.perf_counter() - t0) * 1000

    return {
        'ciphertext_b64': base64.b64encode(ciphertext).decode(),
        'key_b64': base64.b64encode(key).decode(),
        'iv_b64': base64.b64encode(iv).decode(),
        'algorithm': 'AES-256-CBC',
        'original_size': len(image_bytes),
        'ciphertext_size': len(ciphertext),
        'encryption_time_ms': round(enc_ms, 4),
    }


def decrypt_image(ciphertext_b64: str, key_b64: str, iv_b64: str) -> dict:
    """Decrypt AES-256-CBC encrypted image bytes."""
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    t0 = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    dec_ms = (time.perf_counter() - t0) * 1000

    return {
        'image_b64': base64.b64encode(plaintext).decode(),
        'decrypted_size': len(plaintext),
        'decryption_time_ms': round(dec_ms, 4),
        'algorithm': 'AES-256-CBC',
    }


# =====================================================================
# SECURITY ANALYSIS — helpers
# =====================================================================

def _count_bit_differences(b1: bytes, b2: bytes) -> tuple:
    """Count differing bits between two equal-length byte sequences."""
    min_len = min(len(b1), len(b2))
    changed = sum(bin(b1[i] ^ b2[i]).count('1') for i in range(min_len))
    return changed, min_len * 8


def _count_char_differences(h1: str, h2: str) -> tuple:
    """Count differing hex characters between two hex strings."""
    min_len = min(len(h1), len(h2))
    changed = sum(1 for i in range(min_len) if h1[i] != h2[i])
    return changed, min_len


# =====================================================================
# CONFUSION  (same plaintext, different keys)
# =====================================================================

def analyze_confusion(plaintext: str = None) -> dict:
    if not plaintext:
        plaintext = "The quick brown fox jumps over the lazy dog."
    pt_bytes = plaintext.encode('utf-8')
    iv = get_random_bytes(16)          # fixed IV for controlled comparison
    key1 = get_random_bytes(32)
    key2 = get_random_bytes(32)

    ct1 = AES.new(key1, AES.MODE_CBC, iv).encrypt(pad(pt_bytes, AES.block_size))
    ct2 = AES.new(key2, AES.MODE_CBC, iv).encrypt(pad(pt_bytes, AES.block_size))

    cb, tb = _count_bit_differences(ct1, ct2)
    cc, tc = _count_char_differences(ct1.hex(), ct2.hex())

    return {
        'plaintext': plaintext,
        'key1_hex': key1.hex(), 'key2_hex': key2.hex(),
        'ciphertext1_hex': ct1.hex(), 'ciphertext2_hex': ct2.hex(),
        'changed_bits': cb, 'total_bits': tb,
        'bit_change_percentage': round(cb / tb * 100, 2) if tb else 0,
        'changed_chars': cc, 'total_chars': tc,
        'char_change_percentage': round(cc / tc * 100, 2) if tc else 0,
        'note': 'Fixed IV used for controlled comparison only. Never reuse IVs in production.',
    }


# =====================================================================
# DIFFUSION  (slightly different plaintext, same key)
# =====================================================================

def analyze_diffusion(plaintext: str = None) -> dict:
    if not plaintext:
        plaintext = "The quick brown fox jumps over the lazy dog."
    pt_bytes = bytearray(plaintext.encode('utf-8'))
    mod_bytes = bytearray(pt_bytes)
    mod_bytes[0] ^= 0x01                     # flip one bit

    key = get_random_bytes(32)
    iv = get_random_bytes(16)                 # fixed for controlled comparison

    ct1 = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes(pt_bytes), AES.block_size))
    ct2 = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes(mod_bytes), AES.block_size))

    cb, tb = _count_bit_differences(ct1, ct2)
    cc, tc = _count_char_differences(ct1.hex(), ct2.hex())

    return {
        'plaintext_original': plaintext,
        'plaintext_modified': bytes(mod_bytes).decode('utf-8', errors='replace'),
        'key_hex': key.hex(),
        'ciphertext1_hex': ct1.hex(), 'ciphertext2_hex': ct2.hex(),
        'changed_bits': cb, 'total_bits': tb,
        'bit_change_percentage': round(cb / tb * 100, 2) if tb else 0,
        'changed_chars': cc, 'total_chars': tc,
        'char_change_percentage': round(cc / tc * 100, 2) if tc else 0,
        'note': 'In AES-CBC, a 1-bit plaintext change affects the corresponding block and all subsequent blocks.',
    }


# =====================================================================
# AVALANCHE EFFECT  (plaintext + key avalanche)
# =====================================================================

def analyze_avalanche() -> dict:
    plaintext = get_random_bytes(32)       # 2 AES blocks
    key = get_random_bytes(32)
    iv = get_random_bytes(16)              # fixed for comparison

    # --- plaintext avalanche ---
    mod_pt = bytearray(plaintext); mod_pt[0] ^= 0x01
    ct_orig = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes(plaintext), AES.block_size))
    ct_mod_pt = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes(mod_pt), AES.block_size))
    pt_cb, pt_tb = _count_bit_differences(ct_orig, ct_mod_pt)
    pt_cc, pt_tc = _count_char_differences(ct_orig.hex(), ct_mod_pt.hex())

    # --- key avalanche ---
    mod_key = bytearray(key); mod_key[0] ^= 0x01
    ct_orig_k = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes(plaintext), AES.block_size))
    ct_mod_k = AES.new(bytes(mod_key), AES.MODE_CBC, iv).encrypt(pad(bytes(plaintext), AES.block_size))
    k_cb, k_tb = _count_bit_differences(ct_orig_k, ct_mod_k)
    k_cc, k_tc = _count_char_differences(ct_orig_k.hex(), ct_mod_k.hex())

    return {
        'plaintext_avalanche': {
            'original_hex': plaintext.hex(),
            'modified_hex': bytes(mod_pt).hex(),
            'ct_original_hex': ct_orig.hex(),
            'ct_modified_hex': ct_mod_pt.hex(),
            'changed_bits': pt_cb, 'total_bits': pt_tb,
            'avalanche_percentage': round(pt_cb / pt_tb * 100, 2) if pt_tb else 0,
            'changed_chars': pt_cc, 'total_chars': pt_tc,
            'char_change_percentage': round(pt_cc / pt_tc * 100, 2) if pt_tc else 0,
        },
        'key_avalanche': {
            'original_hex': key.hex(),
            'modified_hex': bytes(mod_key).hex(),
            'ct_original_hex': ct_orig_k.hex(),
            'ct_modified_hex': ct_mod_k.hex(),
            'changed_bits': k_cb, 'total_bits': k_tb,
            'avalanche_percentage': round(k_cb / k_tb * 100, 2) if k_tb else 0,
            'changed_chars': k_cc, 'total_chars': k_tc,
            'char_change_percentage': round(k_cc / k_tc * 100, 2) if k_tc else 0,
        },
        'ideal_percentage': 50.0,
        'note': 'AES-CBC avalanche depends on block position. Ideal is ~50%. '
                'Observed values are real experimental results.',
    }


# =====================================================================
# SHA-256 HASHING
# =====================================================================

def generate_sha256(text: str) -> dict:
    t0 = time.perf_counter()
    digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
    ms = (time.perf_counter() - t0) * 1000
    return {
        'input': text, 'digest': digest,
        'digest_length': len(digest), 'digest_bits': 256,
        'generation_time_ms': round(ms, 4), 'algorithm': 'SHA-256',
    }


def demo_preimage(target_prefix: str, max_attempts: int = 200000) -> dict:
    """Toy pre-image search: find input whose SHA-256 starts with given hex prefix."""
    prefix_len = min(len(target_prefix), 5)
    target = target_prefix[:prefix_len].lower()
    t0 = time.perf_counter()
    found = False; found_input = None; attempts = 0
    for i in range(max_attempts):
        candidate = f"attempt_{i}_{os.urandom(4).hex()}"
        h = hashlib.sha256(candidate.encode()).hexdigest()
        attempts += 1
        if h[:prefix_len] == target:
            found = True; found_input = candidate; break
    ms = (time.perf_counter() - t0) * 1000
    return {
        'target_prefix': target, 'prefix_length': prefix_len,
        'found': found, 'found_input': found_input,
        'found_hash': hashlib.sha256(found_input.encode()).hexdigest() if found_input else None,
        'attempts': attempts, 'time_ms': round(ms, 4),
        'note': 'Toy demo with truncated prefix. Full SHA-256 pre-image requires ~2^256 ops.',
    }


def demo_second_preimage(original: str, trunc: int = 3, max_attempts: int = 100000) -> dict:
    """Toy second-pre-image search on truncated hash (default 3 hex chars / 12 bits for interactive speed)."""
    orig_hash = hashlib.sha256(original.encode()).hexdigest()
    target = orig_hash[:trunc]
    t0 = time.perf_counter()
    found = False; found_input = None; attempts = 0
    for i in range(max_attempts):
        candidate = f"sp_{i}_{os.urandom(4).hex()}"
        if candidate == original:
            continue
        h = hashlib.sha256(candidate.encode()).hexdigest()
        attempts += 1
        if h[:trunc] == target:
            found = True; found_input = candidate; break
    ms = (time.perf_counter() - t0) * 1000
    return {
        'original_message': original, 'original_hash': orig_hash,
        'truncated_target': target, 'truncated_length': trunc,
        'found': found, 'found_input': found_input,
        'found_hash': hashlib.sha256(found_input.encode()).hexdigest() if found_input else None,
        'attempts': attempts, 'time_ms': round(ms, 4),
        'note': 'Toy demo with truncated comparison. Full SHA-256 second pre-image is infeasible.',
    }


def demo_collision(truncated_bits: int = 16, max_attempts: int = 200000) -> dict:
    """Birthday-attack collision search on truncated SHA-256."""
    hex_chars = truncated_bits // 4
    t0 = time.perf_counter()
    seen = {}; attempts = 0
    found = False; msg1 = msg2 = hash1 = hash2 = None
    for i in range(max_attempts):
        candidate = f"col_{i}_{os.urandom(4).hex()}"
        h = hashlib.sha256(candidate.encode()).hexdigest()[:hex_chars]
        attempts += 1
        if h in seen and seen[h] != candidate:
            found = True; msg1 = seen[h]; msg2 = candidate
            hash1 = hashlib.sha256(msg1.encode()).hexdigest()
            hash2 = hashlib.sha256(msg2.encode()).hexdigest()
            break
        seen[h] = candidate
    ms = (time.perf_counter() - t0) * 1000
    return {
        'truncated_bits': truncated_bits, 'hex_chars': hex_chars,
        'found': found, 'message1': msg1, 'message2': msg2,
        'hash1': hash1, 'hash2': hash2,
        'truncated_match': hash1[:hex_chars] if hash1 else None,
        'full_hashes_differ': (hash1 != hash2) if hash1 and hash2 else None,
        'attempts': attempts, 'time_ms': round(ms, 4),
        'expected_attempts': f"~{2**(truncated_bits//2):,}",
        'note': f'Birthday attack on {truncated_bits}-bit truncated hash. '
                'Does NOT imply SHA-256 weakness.',
    }


# =====================================================================
# DIGITAL SIGNATURES  (RSA-PSS + SHA-256)
# =====================================================================

def generate_signing_keypair() -> tuple:
    """Generate RSA-2048 key pair for digital signatures (separate from encryption keys)."""
    key = RSA.generate(2048)
    return key.publickey().export_key().decode(), key.export_key().decode()


def sign_message(message: str, private_key_pem: str) -> dict:
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(message.encode('utf-8'))
    t0 = time.perf_counter()
    sig = pss.new(key).sign(h)
    ms = (time.perf_counter() - t0) * 1000
    return {
        'message': message,
        'signature_b64': base64.b64encode(sig).decode(),
        'signature_hex': sig.hex(),
        'signature_size': len(sig),
        'algorithm': 'RSA-PSS-SHA256',
        'signing_time_ms': round(ms, 4),
    }


def verify_signature(message: str, signature_b64: str, public_key_pem: str) -> dict:
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message.encode('utf-8'))
    sig = base64.b64decode(signature_b64)
    t0 = time.perf_counter()
    try:
        pss.new(key).verify(h, sig)
        valid = True
    except (ValueError, TypeError):
        valid = False
    ms = (time.perf_counter() - t0) * 1000
    return {
        'message': message, 'valid': valid,
        'verification_time_ms': round(ms, 4),
        'algorithm': 'RSA-PSS-SHA256',
    }


# =====================================================================
# PERFORMANCE BENCHMARKS
# =====================================================================

def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024*1024):.0f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} B"


def run_text_benchmark(sizes=None, iterations: int = 5) -> list:
    if sizes is None:
        sizes = [1024, 10240, 102400, 512000, 1048576, 5242880]
    results = []
    for sz in sizes:
        data = ('A' * sz).encode('utf-8')
        et, dt = [], []
        for _ in range(iterations):
            k, iv = get_random_bytes(32), get_random_bytes(16)
            t0 = time.perf_counter()
            ct = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))
            et.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
            dt.append((time.perf_counter() - t0) * 1000)
        ae, ad = sum(et)/len(et), sum(dt)/len(dt)
        results.append({
            'size_bytes': sz, 'size_label': _fmt_size(sz),
            'avg_enc_ms': round(ae, 4), 'avg_dec_ms': round(ad, 4),
            'throughput_enc_kbs': round((sz/1024)/(ae/1000), 2) if ae > 0 else 0,
            'throughput_dec_kbs': round((sz/1024)/(ad/1000), 2) if ad > 0 else 0,
            'iterations': iterations,
        })
    return results


def run_image_benchmark(sizes=None, iterations: int = 5) -> list:
    if sizes is None:
        sizes = [1024, 10240, 102400, 512000, 1048576, 5242880]
    results = []
    for sz in sizes:
        data = os.urandom(sz)
        et, dt = [], []
        for _ in range(iterations):
            k, iv = get_random_bytes(32), get_random_bytes(16)
            t0 = time.perf_counter()
            ct = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))
            et.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
            dt.append((time.perf_counter() - t0) * 1000)
        ae, ad = sum(et)/len(et), sum(dt)/len(dt)
        results.append({
            'size_bytes': sz, 'size_label': _fmt_size(sz),
            'avg_enc_ms': round(ae, 4), 'avg_dec_ms': round(ad, 4),
            'throughput_enc_kbs': round((sz/1024)/(ae/1000), 2) if ae > 0 else 0,
            'throughput_dec_kbs': round((sz/1024)/(ad/1000), 2) if ad > 0 else 0,
            'iterations': iterations,
        })
    return results
