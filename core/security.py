import time
import threading
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, render_template, make_response, current_app, session
from core.audit import log_event, get_client_ip
from config import Config

# Controllable clock mechanism for deterministic testing without real sleep
_time_provider = time.time

def get_current_time() -> float:
    """Returns the current timestamp using the configured time provider."""
    return _time_provider()

def set_time_func(func):
    """Overrides the time provider for testing."""
    global _time_provider
    _time_provider = func

def reset_time_func():
    """Resets the time provider back to standard system time."""
    global _time_provider
    _time_provider = time.time


class SecurityManager:
    """
    Core Intrusion Detection System (IDS) and In-Memory Rate Limiter.
    Thread-safe implementation with configurable thresholds.
    
    NOTE: In-memory counters reset automatically when the server restarts.
    """
    def __init__(self):
        self._lock = threading.Lock()
        # IP -> list of timestamp floats for failed logins
        self._failed_logins = defaultdict(list)
        # IP -> float expiry timestamp for active login cooldowns
        self._login_cooldowns = {}
        # (IP, route_key) -> list of timestamp floats for rate-limited requests
        self._request_records = defaultdict(list)
        # IP -> list of timestamp floats for unauthorized access attempts
        self._unauth_records = defaultdict(list)
        # (IP, key) -> last alert timestamp (to avoid duplicate log flood on sustained attacks)
        self._last_alert_time = {}

    def reset_all(self):
        """Resets all in-memory tracking state (used in testing and clean startups)."""
        with self._lock:
            self._failed_logins.clear()
            self._login_cooldowns.clear()
            self._request_records.clear()
            self._unauth_records.clear()
            self._last_alert_time.clear()

    # =========================================================================
    # 1. Intrusion Detection: Failed Login Tracking & Temporary Cooldown
    # =========================================================================
    def record_failed_login(self, ip: str, user_id=None, limit=None, window=None, cooldown=None):
        """
        Records a failed login attempt for the source IP.
        If the failed attempt threshold is reached within the window, triggers a temporary cooldown
        and logs an IDS_SUSPICIOUS_ACTIVITY event.
        
        Returns: (cooldown_triggered: bool, cooldown_duration_or_remaining: int)
        """
        limit = limit or Config.FAILED_LOGIN_LIMIT
        window = window or Config.FAILED_LOGIN_WINDOW
        cooldown = cooldown or Config.LOGIN_COOLDOWN_DURATION
        
        now = get_current_time()
        with self._lock:
            # Prune timestamps outside the rolling window
            valid_attempts = [t for t in self._failed_logins[ip] if now - t < window]
            valid_attempts.append(now)
            self._failed_logins[ip] = valid_attempts
            
            if len(valid_attempts) >= limit:
                cooldown_expires = now + cooldown
                self._login_cooldowns[ip] = cooldown_expires
                # Clear counter on cooldown trigger to avoid duplicate repeated triggers
                self._failed_logins[ip] = []
                
                log_event(
                    user_id=user_id,
                    event_type="IDS_SUSPICIOUS_ACTIVITY",
                    status="TRIGGERED",
                    description=f"Repeated failed logins ({limit} attempts in {window}s) from IP {ip}. Applied {cooldown}s cooldown."
                )
                return True, cooldown
                
            return False, 0

    def check_login_cooldown(self, ip: str):
        """
        Checks if the source IP is currently in a temporary login cooldown.
        Returns: (is_active: bool, seconds_remaining: int)
        """
        now = get_current_time()
        with self._lock:
            expiry = self._login_cooldowns.get(ip, 0)
            if now < expiry:
                return True, int(expiry - now) + 1
            elif ip in self._login_cooldowns:
                del self._login_cooldowns[ip]
            return False, 0

    def record_successful_login(self, ip: str):
        """Resets failed login counters and cooldowns upon valid authentication."""
        with self._lock:
            self._failed_logins.pop(ip, None)
            self._login_cooldowns.pop(ip, None)

    # =========================================================================
    # 2. Rate Limiting & Availability Protection
    # =========================================================================
    def check_rate_limit(self, ip: str, route_key: str, limit: int, window: int):
        """
        Sliding-window rate limiter per (IP, route_key).
        Returns: (allowed: bool, retry_after: int)
        """
        now = get_current_time()
        key = (ip, route_key)
        with self._lock:
            timestamps = self._request_records[key]
            valid_timestamps = [t for t in timestamps if now - t < window]
            
            if len(valid_timestamps) >= limit:
                retry_after = int(window - (now - valid_timestamps[0])) + 1
                return False, max(1, retry_after)
            
            valid_timestamps.append(now)
            self._request_records[key] = valid_timestamps
            return True, 0

    # =========================================================================
    # 3. Intrusion Detection: Unauthorized Access & Enumeration Detection
    # =========================================================================
    def record_unauthorized_access(self, ip: str, user_id, resource_description: str, limit=3, window=300):
        """
        Logs unauthorized access attempt and detects multi-target enumeration / scanning attacks.
        """
        now = get_current_time()
        with self._lock:
            # Log individual unauthorized access
            log_event(user_id, "UNAUTHORIZED_ACCESS", "FAILURE", resource_description, ip_address=ip)
            
            # Track recurring unauthorized activity
            valid_attempts = [t for t in self._unauth_records[ip] if now - t < window]
            valid_attempts.append(now)
            self._unauth_records[ip] = valid_attempts
            
            if len(valid_attempts) >= limit:
                # Avoid log spamming if alert was triggered recently
                last_alert = self._last_alert_time.get((ip, 'unauth_scan'), 0)
                if now - last_alert >= 60:
                    self._last_alert_time[(ip, 'unauth_scan')] = now
                    log_event(
                        user_id=user_id,
                        event_type="IDS_SUSPICIOUS_ACTIVITY",
                        status="TRIGGERED",
                        description=f"Multiple unauthorized resource access attempts ({len(valid_attempts)} in {window}s) detected from IP {ip}."
                    )


# Singleton Security Manager Instance
security_manager = SecurityManager()


def rate_limit_exceeded_response(retry_after: int, message: str = "Too many requests. Please slow down and try again later."):
    """Generates an HTTP 429 response suitable for browser or API clients."""
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        response = jsonify({
            'error': 'Rate limit exceeded',
            'message': message,
            'retry_after': retry_after
        })
        response.status_code = 429
        response.headers['Retry-After'] = str(retry_after)
        return response
    
    try:
        content = render_template('429.html', message=message, retry_after=retry_after)
    except Exception:
        content = f"<h1>429 Too Many Requests</h1><p>{message}</p><p>Please retry in {retry_after} seconds.</p>"
    
    response = make_response(content, 429)
    response.headers['Retry-After'] = str(retry_after)
    return response


def rate_limit(limit_spec, window: int = None, key_prefix: str = None):
    """
    Decorator for route rate limiting.
    Accepts:
      - (max_requests, window_seconds) tuple
      - or string naming a config attribute (e.g. 'RATE_LIMIT_LOGIN')
      - or separate max_requests and window_seconds
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if isinstance(limit_spec, str):
                max_reqs, win_sec = current_app.config.get(limit_spec, (120, 60))
            elif isinstance(limit_spec, (tuple, list)):
                max_reqs, win_sec = limit_spec[0], limit_spec[1]
            elif isinstance(limit_spec, int) and window is not None:
                max_reqs, win_sec = limit_spec, window
            else:
                max_reqs, win_sec = current_app.config.get('RATE_LIMIT_GLOBAL', (120, 60))

            ip = get_client_ip()
            route_key = key_prefix or request.endpoint or request.path
            
            allowed, retry_after = security_manager.check_rate_limit(ip, route_key, max_reqs, win_sec)
            if not allowed:
                user_id = session.get('user_id')
                log_event(
                    user_id=user_id,
                    event_type="RATE_LIMIT_EXCEEDED",
                    status="BLOCKED",
                    description=f"Rate limit exceeded on {request.path} ({max_reqs} requests / {win_sec}s) by IP {ip}"
                )
                return rate_limit_exceeded_response(
                    retry_after,
                    message=f"Rate limit exceeded on this endpoint. Maximum {max_reqs} requests allowed per {win_sec} seconds. Please wait {retry_after} seconds."
                )
            return f(*args, **kwargs)
        return wrapped
    return decorator


import hmac

def can_access_security_monitor(req) -> bool:
    """
    Verifies authorization for the security monitoring dashboard.
    Authorized ONLY when:
      1. Accessed from local server loopback interface (127.0.0.1, ::1, localhost)
      2. Or an explicit administrative SECURITY_MONITOR_KEY is configured AND
         supplied via the secure X-Security-Monitor-Key header (verified with constant-time compare).
    Query parameter passing is disallowed to prevent secret leakage in logs/history.
    """
    client_ip = get_client_ip()
    if client_ip in ('127.0.0.1', '::1', 'localhost'):
        return True
        
    expected_key = current_app.config.get('SECURITY_MONITOR_KEY')
    if not expected_key or not isinstance(expected_key, str) or len(expected_key.strip()) == 0:
        # No remote key configured: remote LAN access is strictly prohibited
        return False
        
    provided_key = req.headers.get('X-Security-Monitor-Key')
    if provided_key and hmac.compare_digest(provided_key.strip(), expected_key.strip()):
        return True
        
    return False
