import os

class Config:
    # A secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY')

    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY environment variable is required")
    
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Database config (Will be used in Phase 2)
    DATABASE = os.path.join(BASE_DIR, 'database', 'ciphershare.db')
    
    # Storage config (Will be used in Phase 5)
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'encrypted_files')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload limit
    
    # Session config (Phase 6 security fix)
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(BASE_DIR, 'storage', 'sessions')
    SESSION_PERMANENT = False
    
    # Server network binding config (Phase 9 LAN support)
    HOST = os.environ.get('CIPHERSHARE_HOST', '0.0.0.0')
    PORT = int(os.environ.get('CIPHERSHARE_PORT', 5000))
    
    # Phase 10 - Intrusion Detection System & Rate Limiting Configuration
    # Failed Login & Cooldown
    FAILED_LOGIN_LIMIT = int(os.environ.get('FAILED_LOGIN_LIMIT', 5))              # Max failed attempts before cooldown
    FAILED_LOGIN_WINDOW = int(os.environ.get('FAILED_LOGIN_WINDOW', 300))          # Window in seconds (5 minutes)
    LOGIN_COOLDOWN_DURATION = int(os.environ.get('LOGIN_COOLDOWN_DURATION', 300))  # Cooldown duration in seconds (5 minutes)
    
    # Route Rate Limits: (max_requests, window_in_seconds)
    # (Documented: in-memory counters reset when the server restarts)
    RATE_LIMIT_LOGIN = (int(os.environ.get('RATE_LIMIT_LOGIN_MAX', 10)), int(os.environ.get('RATE_LIMIT_LOGIN_WIN', 60)))
    RATE_LIMIT_REGISTER = (int(os.environ.get('RATE_LIMIT_REG_MAX', 5)), int(os.environ.get('RATE_LIMIT_REG_WIN', 60)))
    RATE_LIMIT_UPLOAD = (int(os.environ.get('RATE_LIMIT_UPLOAD_MAX', 20)), int(os.environ.get('RATE_LIMIT_UPLOAD_WIN', 60)))
    RATE_LIMIT_GLOBAL = (int(os.environ.get('RATE_LIMIT_GLOBAL_MAX', 120)), int(os.environ.get('RATE_LIMIT_GLOBAL_WIN', 60)))
    
    # Security Monitoring Access Key (Optional secret token for remote administrative access; None by default restricts to localhost)
    SECURITY_MONITOR_KEY = os.environ.get('SECURITY_MONITOR_KEY', None)
    
    @staticmethod
    def init_app(app):
        # Create necessary directories on startup if they don't exist
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(os.path.dirname(Config.DATABASE), exist_ok=True)
        os.makedirs(Config.SESSION_FILE_DIR, exist_ok=True)
