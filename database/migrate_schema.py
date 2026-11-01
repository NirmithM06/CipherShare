"""
Database Schema Migration for CipherShare Cryptographic File-Sharing Integration
Adds:
- Users: signing_public_key, encrypted_signing_private_key
- Files: file_hash, hash_algorithm, hash_time_ms, signature_id, file_size_bytes
- DigitalSignatures: file_id, signing_time_ms
- PerformanceMetrics: granular timing columns
"""

import sqlite3
import os

def migrate_database():
    db_path = os.path.join(os.path.dirname(__file__), 'ciphershare.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # 1. Users table
    cols = [r[1] for r in c.execute('PRAGMA table_info(Users)').fetchall()]
    if 'signing_public_key' not in cols:
        c.execute('ALTER TABLE Users ADD COLUMN signing_public_key TEXT')
        print("Added Users.signing_public_key")
    if 'encrypted_signing_private_key' not in cols:
        c.execute('ALTER TABLE Users ADD COLUMN encrypted_signing_private_key TEXT')
        print("Added Users.encrypted_signing_private_key")

    # 2. Files table
    fcols = [r[1] for r in c.execute('PRAGMA table_info(Files)').fetchall()]
    if 'file_hash' not in fcols:
        c.execute('ALTER TABLE Files ADD COLUMN file_hash TEXT')
        print("Added Files.file_hash")
    if 'hash_algorithm' not in fcols:
        c.execute("ALTER TABLE Files ADD COLUMN hash_algorithm TEXT DEFAULT 'SHA-256'")
        print("Added Files.hash_algorithm")
    if 'hash_time_ms' not in fcols:
        c.execute('ALTER TABLE Files ADD COLUMN hash_time_ms REAL')
        print("Added Files.hash_time_ms")
    if 'signature_id' not in fcols:
        c.execute('ALTER TABLE Files ADD COLUMN signature_id INTEGER')
        print("Added Files.signature_id")
    if 'file_size_bytes' not in fcols:
        c.execute('ALTER TABLE Files ADD COLUMN file_size_bytes INTEGER')
        print("Added Files.file_size_bytes")

    # 3. DigitalSignatures table
    scols = [r[1] for r in c.execute('PRAGMA table_info(DigitalSignatures)').fetchall()]
    if 'file_id' not in scols:
        c.execute('ALTER TABLE DigitalSignatures ADD COLUMN file_id INTEGER')
        print("Added DigitalSignatures.file_id")
    if 'signing_time_ms' not in scols:
        c.execute('ALTER TABLE DigitalSignatures ADD COLUMN signing_time_ms REAL')
        print("Added DigitalSignatures.signing_time_ms")

    # 4. PerformanceMetrics table
    pcols = [r[1] for r in c.execute('PRAGMA table_info(PerformanceMetrics)').fetchall()]
    timing_cols = [
        'file_id', 'enc_time_ms', 'key_wrap_time_ms', 'hmac_time_ms', 
        'hash_time_ms', 'sig_time_ms', 'dec_time_ms', 'key_unwrap_time_ms', 
        'hmac_verify_time_ms', 'hash_verify_time_ms', 'sig_verify_time_ms'
    ]
    for col in timing_cols:
        if col not in pcols:
            c.execute(f'ALTER TABLE PerformanceMetrics ADD COLUMN {col} REAL')
            print(f"Added PerformanceMetrics.{col}")

    conn.commit()
    conn.close()
    print("Database migration completed successfully.")

if __name__ == '__main__':
    migrate_database()
