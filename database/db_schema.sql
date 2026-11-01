CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT,
    encrypted_private_key TEXT,
    signing_public_key TEXT,
    encrypted_signing_private_key TEXT
);

CREATE TABLE IF NOT EXISTS AuditLogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    ip_address TEXT,
    event_type TEXT,
    status TEXT,
    description TEXT,
    FOREIGN KEY(user_id) REFERENCES Users(id)
);

CREATE TABLE IF NOT EXISTS Files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    encrypted_path TEXT,
    hmac_hash TEXT,
    encrypted_aes_key TEXT,
    iv TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    file_hash TEXT,
    hash_algorithm TEXT DEFAULT 'SHA-256',
    hash_time_ms REAL,
    signature_id INTEGER,
    file_size_bytes INTEGER,
    FOREIGN KEY(sender_id) REFERENCES Users(id),
    FOREIGN KEY(receiver_id) REFERENCES Users(id)
);

CREATE TABLE IF NOT EXISTS PerformanceMetrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    operation_type TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    crypto_duration_ms REAL,
    total_duration_ms REAL NOT NULL,
    status TEXT NOT NULL,
    details TEXT,
    file_id INTEGER,
    enc_time_ms REAL,
    key_wrap_time_ms REAL,
    hmac_time_ms REAL,
    hash_time_ms REAL,
    sig_time_ms REAL,
    dec_time_ms REAL,
    key_unwrap_time_ms REAL,
    hmac_verify_time_ms REAL,
    hash_verify_time_ms REAL,
    sig_verify_time_ms REAL
);

CREATE TABLE IF NOT EXISTS TrafficActivity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    endpoint TEXT,
    method TEXT,
    status_code INTEGER,
    payload_size_bytes INTEGER DEFAULT 0,
    event_category TEXT NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS DigitalSignatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    signature TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm TEXT DEFAULT 'RSA-PSS-SHA256',
    verified INTEGER DEFAULT 0,
    file_id INTEGER,
    signing_time_ms REAL,
    FOREIGN KEY(user_id) REFERENCES Users(id),
    FOREIGN KEY(file_id) REFERENCES Files(id)
);
