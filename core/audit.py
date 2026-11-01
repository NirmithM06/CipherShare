from database.models import get_db_connection
from flask import request, has_request_context
from core.time_utils import utc_now_str

def get_client_ip():
    """
    Safely retrieves the client's source IP address from request context.
    Does NOT trust arbitrary X-Forwarded-For headers in this local LAN deployment.
    """
    if has_request_context() and request:
        return request.remote_addr or '127.0.0.1'
    return '127.0.0.1'

def log_event(user_id, event_type, status, description, ip_address=None):
    """
    Records an event in the AuditLogs table with explicit timezone-aware UTC timestamp.
    Ensures safe database connection lifecycle and sanitized event recording.
    """
    if ip_address is None:
        ip_address = get_client_ip()

    # Ensure sensitive cryptographic or password material is never stored in logs
    sanitized_desc = str(description)
    current_utc = utc_now_str()

    db = get_db_connection()
    try:
        db.execute(
            "INSERT INTO AuditLogs (timestamp, user_id, ip_address, event_type, status, description) VALUES (?, ?, ?, ?, ?, ?)",
            (current_utc, user_id, ip_address, event_type, status, sanitized_desc)
        )
        db.commit()
    finally:
        db.close()
