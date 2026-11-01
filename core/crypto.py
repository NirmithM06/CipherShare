import base64
import time
import json
import zipfile
import io
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss

def generate_rsa_keypair(password: str) -> tuple[str, str]:
    """Generates an RSA key pair and returns (public_key_pem, encrypted_private_key_pem)"""
    key = RSA.generate(2048)
    private_key_pem = key.export_key(
        passphrase=password,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    ).decode('utf-8')
    public_key_pem = key.publickey().export_key().decode('utf-8')
    return public_key_pem, private_key_pem

def generate_signing_keypair(password: str) -> tuple[str, str]:
    """
    Generates a dedicated RSA-2048 key pair for digital signatures.
    Returns (signing_public_key_pem, encrypted_signing_private_key_pem).
    Private signing key is encrypted at rest using the user's password.
    """
    key = RSA.generate(2048)
    private_key_pem = key.export_key(
        passphrase=password,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    ).decode('utf-8')
    public_key_pem = key.publickey().export_key().decode('utf-8')
    return public_key_pem, private_key_pem

def sign_file_hash(file_hash_hex: str, encrypted_signing_private_key_pem: str, password: str) -> tuple[str, float]:
    """
    Signs the SHA-256 file hash using RSA-PSS with SHA-256.
    Returns (signature_b64, duration_ms).
    """
    t0 = time.perf_counter()
    signing_key = RSA.import_key(encrypted_signing_private_key_pem, passphrase=password)
    h = SHA256.new(file_hash_hex.encode('utf-8'))
    signature = pss.new(signing_key).sign(h)
    duration_ms = (time.perf_counter() - t0) * 1000.0
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return signature_b64, duration_ms

def verify_file_hash_signature(file_hash_hex: str, signature_b64: str, signing_public_key_pem: str) -> tuple[bool, float, str]:
    """
    Verifies an RSA-PSS digital signature over the SHA-256 file hash.
    Returns (is_valid, duration_ms, error_msg).
    """
    t0 = time.perf_counter()
    try:
        public_key = RSA.import_key(signing_public_key_pem)
        h = SHA256.new(file_hash_hex.encode('utf-8'))
        signature = base64.b64decode(signature_b64)
        pss.new(public_key).verify(h, signature)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return True, duration_ms, ""
    except (ValueError, TypeError) as e:
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return False, duration_ms, str(e)

def compute_file_sha256(file_data: bytes) -> tuple[str, float]:
    """
    Computes SHA-256 digest of original plaintext file data.
    Returns (digest_hex, duration_ms).
    """
    t0 = time.perf_counter()
    digest = SHA256.new(file_data).hexdigest()
    duration_ms = (time.perf_counter() - t0) * 1000.0
    return digest, duration_ms

def encrypt_file_data(file_data: bytes, receiver_public_key_pem: str, return_timings: bool = False):
    """
    Encrypts file data using a random AES-256-CBC key.
    Calculates HMAC-SHA256 over IV || encrypted_data using an HMAC key derived from AES key.
    The AES key is encrypted using the receiver's RSA public key (RSA-OAEP).
    Returns (encrypted_file_data, encrypted_aes_key_b64, iv_b64, hmac_b64) or
            (encrypted_file_data, encrypted_aes_key_b64, iv_b64, hmac_b64, timings) if return_timings=True.
    """
    timings = {}
    
    # 1. Generate AES-256 key and IV
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    
    # 2. Encrypt the file data
    t0 = time.perf_counter()
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_file_data = cipher_aes.encrypt(pad(file_data, AES.block_size))
    timings['enc_time_ms'] = (time.perf_counter() - t0) * 1000.0
    
    # 3. Derive HMAC key using HKDF and calculate HMAC
    t0 = time.perf_counter()
    hmac_key = HKDF(aes_key, 32, salt=b'', hashmod=SHA256, context=b'hmac_key_derivation')
    mac = HMAC.new(hmac_key, digestmod=SHA256)
    mac.update(iv)
    mac.update(encrypted_file_data)
    hmac_tag = mac.digest()
    timings['hmac_time_ms'] = (time.perf_counter() - t0) * 1000.0
    
    # 4. Encrypt the AES key with receiver's RSA public key (RSA-OAEP)
    t0 = time.perf_counter()
    recipient_key = RSA.import_key(receiver_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    timings['key_wrap_time_ms'] = (time.perf_counter() - t0) * 1000.0
    
    # 5. Encode keys for storage
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    hmac_b64 = base64.b64encode(hmac_tag).decode('utf-8')
    
    if return_timings:
        return encrypted_file_data, encrypted_aes_key_b64, iv_b64, hmac_b64, timings
    return encrypted_file_data, encrypted_aes_key_b64, iv_b64, hmac_b64

def decrypt_file_data(encrypted_file_data: bytes, encrypted_aes_key_b64: str, iv_b64: str, hmac_b64: str,
                      receiver_private_key_pem: str, receiver_password: str, return_timings: bool = False):
    """
    Decrypts the file data after verifying HMAC integrity.
    Returns decrypted_file_data, or (decrypted_file_data, timings) if return_timings=True.
    Raises ValueError("INTEGRITY_CHECK_FAILED") if HMAC verification fails.
    """
    timings = {}
    
    # 1. Decode keys
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    iv = base64.b64decode(iv_b64)
    stored_hmac = base64.b64decode(hmac_b64)
    
    # 2. Decrypt the private key & unwrap AES key
    t0 = time.perf_counter()
    private_key = RSA.import_key(receiver_private_key_pem, passphrase=receiver_password)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    timings['key_unwrap_time_ms'] = (time.perf_counter() - t0) * 1000.0
    
    # 3. Derive HMAC key using HKDF and Verify HMAC
    t0 = time.perf_counter()
    hmac_key = HKDF(aes_key, 32, salt=b'', hashmod=SHA256, context=b'hmac_key_derivation')
    mac = HMAC.new(hmac_key, digestmod=SHA256)
    mac.update(iv)
    mac.update(encrypted_file_data)
    
    try:
        mac.verify(stored_hmac)
    except ValueError:
        raise ValueError("INTEGRITY_CHECK_FAILED")
    timings['hmac_verify_time_ms'] = (time.perf_counter() - t0) * 1000.0
        
    # 4. Decrypt the file data using AES key
    t0 = time.perf_counter()
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_file_data = unpad(cipher_aes.decrypt(encrypted_file_data), AES.block_size)
    timings['dec_time_ms'] = (time.perf_counter() - t0) * 1000.0
    
    if return_timings:
        return decrypted_file_data, timings
    return decrypted_file_data

def create_encrypted_package(file_row: dict, sender_record: dict, receiver_record: dict, encrypted_data: bytes) -> bytes:
    """
    Builds a secure .cspkg portable encrypted package containing:
    - payload.enc: Encrypted file ciphertext
    - metadata.json: Cryptographic parameters, wrapped AES key, IV, HMAC, SHA-256 digest,
                     RSA-PSS digital signature, algorithms, and sender public keys.
    Does NOT contain plaintext AES keys or private keys.
    """
    f_dict = dict(file_row) if file_row else {}
    s_dict = dict(sender_record) if sender_record else {}
    r_dict = dict(receiver_record) if receiver_record else {}

    metadata = {
        "format": "CipherShare-Package",
        "version": "2.0",
        "created_at": f_dict.get("timestamp"),
        "file": {
            "filename": f_dict.get("filename"),
            "size_bytes": f_dict.get("file_size_bytes") or len(encrypted_data),
            "sha256_digest": f_dict.get("file_hash"),
            "hash_algorithm": f_dict.get("hash_algorithm", "SHA-256")
        },
        "encryption": {
            "cipher": "AES-256-CBC",
            "iv_b64": f_dict.get("iv"),
            "key_protection": "RSA-2048-OAEP",
            "encrypted_aes_key_b64": f_dict.get("encrypted_aes_key"),
            "receiver_id": f_dict.get("receiver_id"),
            "receiver_username": r_dict.get("username")
        },
        "integrity": {
            "algorithm": "HMAC-SHA256",
            "kdf": "HKDF-SHA256",
            "hmac_b64": f_dict.get("hmac_hash")
        },
        "signature": {
            "algorithm": "RSA-PSS-SHA256",
            "signature_b64": f_dict.get("signature_b64"),
            "signer_id": f_dict.get("sender_id"),
            "signer_username": s_dict.get("username"),
            "signer_signing_public_key": s_dict.get("signing_public_key"),
            "signer_encryption_public_key": s_dict.get("public_key")
        }
    }

    pkg_buf = io.BytesIO()
    with zipfile.ZipFile(pkg_buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('metadata.json', json.dumps(metadata, indent=2))
        zf.writestr('payload.enc', encrypted_data)
        zf.writestr('README.txt', (
            "CipherShare Secure Encrypted Package (.cspkg)\n"
            "This package contains AES-256-CBC encrypted data protected with RSA-OAEP and signed with RSA-PSS.\n"
            "It can only be decrypted by the intended recipient using their private key.\n"
        ))
    return pkg_buf.getvalue()
