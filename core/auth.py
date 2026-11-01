from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from database.models import get_db_connection
from core.audit import log_event, get_client_ip
from core.security import security_manager, rate_limit
from core.collector import live_collector
from config import Config
import functools

auth = Blueprint('auth', __name__)

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

@auth.route('/register', methods=('GET', 'POST'))
@rate_limit('RATE_LIMIT_REGISTER', key_prefix='register')
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db_connection()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                from core.crypto import generate_rsa_keypair, generate_signing_keypair
                public_key, encrypted_private_key = generate_rsa_keypair(password)
                signing_public_key, encrypted_signing_private_key = generate_signing_keypair(password)
                
                db.execute(
                    """INSERT INTO Users (username, password_hash, public_key, encrypted_private_key, 
                                          signing_public_key, encrypted_signing_private_key) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (username, generate_password_hash(password), public_key, encrypted_private_key,
                     signing_public_key, encrypted_signing_private_key),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
                log_event(None, "REGISTER", "FAILURE", error)
                live_collector.record_traffic_event(
                    ip_address=get_client_ip(),
                    endpoint="/register",
                    method="POST",
                    status_code=400,
                    event_category="AUTHENTICATION",
                    details=f"Registration failed: {error}"
                )
            else:
                user_id_row = db.execute('SELECT id FROM Users WHERE username = ?', (username,)).fetchone()
                log_event(user_id_row['id'], "REGISTER", "SUCCESS", "User registered")
                live_collector.record_traffic_event(
                    ip_address=get_client_ip(),
                    endpoint="/register",
                    method="POST",
                    status_code=302,
                    event_category="AUTHENTICATION",
                    details=f"User registered: {username}"
                )
                flash('Registration successful! Please log in.', 'success')
                db.close()
                return redirect(url_for('auth.login'))
            finally:
                db.close()

        flash(error, 'error')

    return render_template('register.html')

@auth.route('/login', methods=('GET', 'POST'))
@rate_limit('RATE_LIMIT_LOGIN', key_prefix='login')
def login():
    if request.method == 'POST':
        client_ip = get_client_ip()
        
        # 1. Intrusion Detection: Check if client IP is in active cooldown
        is_in_cooldown, remaining = security_manager.check_login_cooldown(client_ip)
        if is_in_cooldown:
            log_event(
                user_id=None,
                event_type="LOGIN_RATE_LIMITED",
                status="BLOCKED",
                description=f"Login attempt blocked by cooldown for IP {client_ip} ({remaining}s remaining)"
            )
            live_collector.record_traffic_event(
                ip_address=client_ip,
                endpoint="/login",
                method="POST",
                status_code=429,
                event_category="RATE_LIMIT",
                details=f"Login blocked by cooldown ({remaining}s remaining)"
            )
            flash(f"Too many failed login attempts. Login temporarily disabled. Please try again in {remaining} seconds.", "error")
            return render_template('login.html'), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        db = get_db_connection()
        user = db.execute(
            'SELECT * FROM Users WHERE username = ?', (username,)
        ).fetchone()

        # 2. Verify credentials
        if user is None or not check_password_hash(user['password_hash'], password):
            db.close()
            user_id = user['id'] if user else None
            # Record failed login in IDS
            cooldown_triggered, cooldown_time = security_manager.record_failed_login(
                client_ip,
                user_id=user_id,
                limit=Config.FAILED_LOGIN_LIMIT,
                window=Config.FAILED_LOGIN_WINDOW,
                cooldown=Config.LOGIN_COOLDOWN_DURATION
            )
            
            # Log failed login
            log_event(user_id, "LOGIN_FAILURE", "FAILURE", "Incorrect username or password")
            live_collector.record_traffic_event(
                ip_address=client_ip,
                endpoint="/login",
                method="POST",
                status_code=401,
                event_category="AUTHENTICATION",
                details="Failed login attempt"
            )
            
            if cooldown_triggered:
                flash(f"Too many failed login attempts. Login cooldown applied for {cooldown_time} seconds.", "error")
                return render_template('login.html'), 429
            else:
                flash("Incorrect username or password.", "error")
                return render_template('login.html')

        # Provision persistent signing keypair if user was created before migration
        if not user['signing_public_key'] or not user['encrypted_signing_private_key']:
            from core.crypto import generate_signing_keypair
            spub, spriv = generate_signing_keypair(password)
            db.execute(
                "UPDATE Users SET signing_public_key = ?, encrypted_signing_private_key = ? WHERE id = ?",
                (spub, spriv, user['id'])
            )
            db.commit()
            user = db.execute('SELECT * FROM Users WHERE id = ?', (user['id'],)).fetchone()
        
        db.close()

        # 3. Successful authentication
        security_manager.record_successful_login(client_ip)
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        # Store passphrase in server-side session for private key decryption and signing operations
        session['passphrase'] = password
        # Also maintain session signing keys for standalone educational digital signature playground
        session['signing_public_key'] = user['signing_public_key']
        log_event(user['id'], "LOGIN_SUCCESS", "SUCCESS", "User logged in")
        live_collector.record_traffic_event(
            ip_address=client_ip,
            endpoint="/login",
            method="POST",
            status_code=302,
            event_category="AUTHENTICATION",
            details=f"Successful login for user {user['username']}"
        )
        return redirect(url_for('crypto.overview'))

    return render_template('login.html')

@auth.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_event(user_id, "LOGOUT", "SUCCESS", "User logged out")
        live_collector.record_traffic_event(
            ip_address=get_client_ip(),
            endpoint="/logout",
            method="GET",
            status_code=302,
            event_category="AUTHENTICATION",
            details="User logged out"
        )
    session.clear()
    return redirect(url_for('index'))
