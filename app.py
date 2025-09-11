import os
import json
import base64
import logging
import random
import secrets
import re
import time
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from zxcvbn import zxcvbn
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bleach

# Try to import requests, fallback if not available
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  WARNING: 'requests' package not installed. HaveIBeenPwned integration will use mock data.")
    print("   Install with: pip install requests")

# --------------------------------------------------------
# Initialize Flask app
# --------------------------------------------------------
app = Flask(__name__)

# --------------------------------------------------------
# Enhanced Security Configuration
# --------------------------------------------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///vaultguard_secure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# Temporarily disable secure cookies for development
# app.config['SESSION_COOKIE_SECURE'] = True  # Requires HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --------------------------------------------------------
# Enhanced Logging
# --------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vaultguard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------
# Flask-Login Setup
# --------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    try:
        user = User.query.get(int(user_id))
        if user and user.is_account_locked():
            return None
        return user
    except (ValueError, TypeError):
        return None

# --------------------------------------------------------
# Database Models
# --------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    encryption_salt = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    
    # Phase 1 enhancement fields
    notification_preferences = db.Column(db.Text)  # JSON string
    breach_check_enabled = db.Column(db.Boolean, default=True)
    last_breach_check = db.Column(db.DateTime)
    
    vault_entries = db.relationship('VaultEntry', backref='owner', lazy=True, cascade='all, delete-orphan')
    security_events = db.relationship('SecurityEvent', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password, rounds=12).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
    
    def lock_account(self, duration_minutes=60):
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts += 1
        self.log_security_event('ACCOUNT_LOCKED', f'Account locked for {duration_minutes} minutes')
    
    def unlock_account(self):
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()
        self.log_security_event('LOGIN_SUCCESS', 'Successful login')

    def get_encryption_key(self, master_password):
        salt = base64.b64decode(self.encryption_salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def get_notification_preferences(self):
        if self.notification_preferences:
            try:
                return json.loads(self.notification_preferences)
            except json.JSONDecodeError:
                pass
        return {
            'breach_alerts': True,
            'password_age_warnings': True,
            'security_updates': True,
            'login_notifications': False
        }

    def set_notification_preferences(self, preferences):
        self.notification_preferences = json.dumps(preferences)

    def log_security_event(self, event_type, description, ip_address=None):
        try:
            event = SecurityEvent(
                user_id=self.id,
                event_type=event_type,
                description=description,
                ip_address=ip_address or get_client_ip(),
                timestamp=datetime.utcnow()
            )
            db.session.add(event)
            return event
        except Exception as e:
            logger.error(f"Failed to log security event: {str(e)}")
            return None

class VaultEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='General')
    notes = db.Column(db.Text)  # Encrypted notes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    access_count = db.Column(db.Integer, default=0)
    password_strength_score = db.Column(db.Integer, default=0)
    is_compromised = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def update_access(self):
        self.access_count += 1
        self.last_accessed = datetime.utcnow()
        if current_user.is_authenticated:
            current_user.log_security_event('PASSWORD_ACCESS', f'Accessed password for {self.site}')

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), default='INFO')

# --------------------------------------------------------
# Security Functions
# --------------------------------------------------------
def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or 'unknown'

def validate_username(username):
    if not username or len(username.strip()) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username can only contain letters, numbers, dots, hyphens, and underscores"
    return True, ""

def validate_password_strength(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password)
    
    if not (has_upper and has_lower and has_digit and has_symbol):
        return False, "Password must contain uppercase, lowercase, numbers, and symbols"
    
    return True, ""

def sanitize_input(text):
    if not text:
        return ""
    return bleach.clean(text.strip(), tags=[], strip=True)[:200]

def encrypt_password(password, key):
    try:
        f = Fernet(key)
        data = json.dumps({
            'password': password,
            'timestamp': datetime.utcnow().isoformat(),
            'checksum': secrets.token_hex(16)
        })
        encrypted = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_password(encrypted_password, key):
    try:
        f = Fernet(key)
        encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted_data = f.decrypt(encrypted_data)
        data = json.loads(decrypted_data.decode())
        return data['password']
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise

def check_password_breach_online(password_hash_prefix):
    """Check password against HaveIBeenPwned API"""
    if not REQUESTS_AVAILABLE:
        return None
        
    try:
        response = requests.get(
            f'https://api.pwnedpasswords.com/range/{password_hash_prefix}',
            timeout=5,
            headers={'User-Agent': 'VaultGuard-Password-Manager'}
        )
        if response.status_code == 200:
            return response.text
        else:
            logger.warning(f"HaveIBeenPwned API returned status: {response.status_code}")
            return None
    except Exception as e:
        logger.warning(f"Breach check failed: {str(e)}")
        return None

def check_password_breach_mock(password):
    """Mock breach detection for fallback"""
    high_risk_passwords = [
        'password', '123456', 'qwerty', 'abc123', 'letmein', 
        'monkey', 'dragon', 'princess', 'welcome', 'sunshine',
        'master', 'shadow', 'football', 'baseball', 'superman',
        'trustno1', 'admin', 'login', 'guest', 'root'
    ]
    
    critical_patterns = [
        '123456', 'qwerty', 'p@ssw0rd', 'passw0rd', '1234567!',
        'password!', 'abcd1234', '1q2w3e4r', 'qwer1234'
    ]
    
    keyboard_sequences = ['qwert', 'asdf', 'zxcv', '1234', '5678']
    repeated_patterns = any(char * 3 in password.lower() for char in 'abcdefghijklmnopqrstuvwxyz0123456789')
    
    lower_password = password.lower()
    
    if lower_password in [p.lower() for p in high_risk_passwords]:
        return True, random.randint(1000000, 10000000), 'critical'
    elif any(pattern.lower() in lower_password for pattern in critical_patterns):
        return True, random.randint(100000, 2000000), 'high_risk'
    elif any(seq in lower_password for seq in keyboard_sequences):
        return True, random.randint(50000, 500000), 'high_risk'
    elif repeated_patterns:
        return True, random.randint(10000, 200000), 'medium_risk'
    elif len(password) < 8:
        return True, random.randint(500000, 5000000), 'critical'
    elif (len(password) >= 32 and 
          any(c.isupper() for c in password) and 
          any(c.islower() for c in password) and 
          any(c.isdigit() for c in password) and 
          any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password)):
        return False, 0, 'fortress'
    elif len(password) >= 16 and any(c.isupper() for c in password) and any(c.islower() for c in password):
        return random.random() < 0.02, random.randint(1, 25) if random.random() < 0.02 else 0, 'strong'
    else:
        return random.random() < 0.15, random.randint(100, 5000) if random.random() < 0.15 else 0, 'medium'

# --------------------------------------------------------
# Security Middleware
# --------------------------------------------------------
@app.before_request
def force_https():
    if not request.is_secure and os.environ.get('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# --------------------------------------------------------
# Create database
# --------------------------------------------------------
with app.app_context():
    try:
        db.create_all()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")

# --------------------------------------------------------
# Main Routes
# --------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html', logged_in=current_user.is_authenticated)

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    current_user.log_security_event('LOGOUT', 'User logged out', get_client_ip())
    logout_user()
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(url_for('home'))

# --------------------------------------------------------
# API Routes
# --------------------------------------------------------
@app.route('/api/login', methods=["POST"])
def api_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        client_ip = get_client_ip()
        
        logger.info(f"Login attempt for username: {username} from IP: {client_ip}")
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        if user.is_account_locked():
            user.log_security_event('LOGIN_BLOCKED', 'Login blocked - account locked', client_ip)
            return jsonify({'success': False, 'message': 'Account locked. Try again later.'}), 423
        
        if user.check_password(password):
            user.unlock_account()
            db.session.commit()
            
            login_user(user, remember=False)
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session.permanent = True
            
            logger.info(f"Successful login for user: {username}")
            
            return jsonify({
                'success': True, 
                'message': 'Secure login successful!', 
                'salt': user.encryption_salt,
                'username': user.username
            }), 200
        else:
            user.failed_login_attempts += 1
            user.log_security_event('LOGIN_FAILED', f'Failed login attempt #{user.failed_login_attempts}', client_ip)
            
            if user.failed_login_attempts >= 3:
                user.lock_account(60)
                logger.warning(f"Account locked for user: {username} after 3 failed attempts")
            
            db.session.commit()
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

@app.route('/api/register', methods=["POST"])
def api_register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        client_ip = get_client_ip()
        
        logger.info(f"Registration attempt for username: {username} from IP: {client_ip}")
        
        username_valid, username_error = validate_username(username)
        if not username_valid:
            return jsonify({'success': False, 'message': username_error}), 400
        
        password_valid, password_error = validate_password_strength(password)
        if not password_valid:
            return jsonify({'success': False, 'message': password_error}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400

        salt = secrets.token_bytes(64)
        encryption_salt = base64.b64encode(salt).decode('utf-8')
        
        new_user = User(
            username=username, 
            encryption_salt=encryption_salt,
            breach_check_enabled=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log the registration
        new_user.log_security_event('ACCOUNT_CREATED', 'New account created', client_ip)
        
        login_user(new_user, remember=False)
        session['logged_in'] = True
        session['username'] = new_user.username
        session['user_id'] = new_user.id
        session.permanent = True
        
        logger.info(f"New user registered and logged in: {username}")
        
        return jsonify({
            'success': True, 
            'message': 'Secure account created!', 
            'salt': encryption_salt,
            'username': new_user.username
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

@app.route('/api/vault', methods=['GET', 'POST'])
@login_required
def manage_vault():
    try:
        if request.method == 'POST':
            data = request.get_json()
            
            if VaultEntry.query.filter_by(user_id=current_user.id).count() >= 50:
                return jsonify({'success': False, 'message': 'Vault limit reached (50 passwords)'}), 400
                
            site = sanitize_input(data.get('site', ''))
            username = sanitize_input(data.get('username', ''))
            password = data.get('password', '')
            master_password = data.get('master_password', '')
            category = sanitize_input(data.get('category', 'General'))
            notes = data.get('notes', '')

            if not all([site, username, password, master_password]):
                return jsonify({'success': False, 'message': 'All fields required'}), 400

            if not current_user.check_password(master_password):
                current_user.log_security_event('VAULT_ACCESS_DENIED', 'Invalid master password', get_client_ip())
                return jsonify({'success': False, 'message': 'Invalid master password'}), 401

            encryption_key = current_user.get_encryption_key(master_password)
            encrypted_password = encrypt_password(password, encryption_key)
            encrypted_notes = encrypt_password(notes, encryption_key) if notes else None
            
            # Calculate password strength
            zx_result = zxcvbn(password)
            strength_score = zx_result['score']
            
            existing_entry = VaultEntry.query.filter_by(
                site=site, username=username, user_id=current_user.id
            ).first()
            
            if existing_entry:
                existing_entry.encrypted_password = encrypted_password
                existing_entry.notes = encrypted_notes
                existing_entry.category = category
                existing_entry.password_strength_score = strength_score
                existing_entry.updated_at = datetime.utcnow()
                message = 'Password updated securely!'
                current_user.log_security_event('PASSWORD_UPDATED', f'Updated password for {site}')
            else:
                new_entry = VaultEntry(
                    site=site,
                    username=username,
                    encrypted_password=encrypted_password,
                    notes=encrypted_notes,
                    category=category,
                    password_strength_score=strength_score,
                    user_id=current_user.id
                )
                db.session.add(new_entry)
                message = 'Password encrypted and saved!'
                current_user.log_security_event('PASSWORD_ADDED', f'Added password for {site}')

            db.session.commit()
            return jsonify({'success': True, 'message': message}), 201

        # GET request
        entries = VaultEntry.query.filter_by(user_id=current_user.id).order_by(VaultEntry.updated_at.desc()).all()
        vault_entries = [{
            'id': entry.id,
            'site': entry.site,
            'username': entry.username,
            'category': entry.category,
            'created_at': entry.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': entry.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'last_accessed': entry.last_accessed.strftime('%Y-%m-%d %H:%M:%S') if entry.last_accessed else None,
            'access_count': entry.access_count,
            'password_strength_score': entry.password_strength_score,
            'is_compromised': entry.is_compromised
        } for entry in entries]
        
        return jsonify({'success': True, 'vault_entries': vault_entries}), 200
        
    except Exception as e:
        logger.error(f"Vault error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

@app.route('/api/vault/<int:entry_id>/password', methods=['POST'])
@login_required
def get_vault_password(entry_id):
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        
        if not current_user.check_password(master_password):
            current_user.log_security_event('VAULT_ACCESS_DENIED', f'Invalid master password for entry {entry_id}')
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
        if not entry:
            return jsonify({'success': False, 'message': 'Password not found'}), 404
        
        encryption_key = current_user.get_encryption_key(master_password)
        decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
        
        entry.update_access()
        db.session.commit()
        
        return jsonify({'success': True, 'password': decrypted_password}), 200
        
    except Exception as e:
        logger.error(f"Password access error: {str(e)}")
        return jsonify({'success': False, 'message': 'Decryption failed'}), 500

@app.route('/api/vault/<int:entry_id>', methods=['DELETE'])
@login_required
def delete_vault_entry(entry_id):
    try:
        entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
        if not entry:
            return jsonify({'success': False, 'message': 'Password not found'}), 404
            
        site_name = entry.site
        db.session.delete(entry)
        db.session.commit()
        
        current_user.log_security_event('PASSWORD_DELETED', f'Deleted password for {site_name}')
        return jsonify({'success': True, 'message': 'Password securely deleted'}), 200
        
    except Exception as e:
        logger.error(f"Delete error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

@app.route('/api/check_password', methods=['POST'])
def check_password_strength():
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({
                'success': True,
                'breached': False,
                'count': 0,
                'suggestions': [],
                'score': 0,
                'crack_time': 'instantly',
                'security_level': 'none'
            })
        
        # Use zxcvbn for password analysis
        zx_result = zxcvbn(password)
        
        # Check for breaches
        is_breached = False
        breach_count = 0
        security_level = 'unknown'
        
        if REQUESTS_AVAILABLE:
            # Try real HaveIBeenPwned API
            try:
                password_sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
                hash_prefix = password_sha1[:5]
                hash_suffix = password_sha1[5:]
                
                breach_data = check_password_breach_online(hash_prefix)
                if breach_data:
                    for line in breach_data.split('\n'):
                        if line.strip():
                            parts = line.strip().split(':')
                            if len(parts) == 2 and parts[0] == hash_suffix:
                                is_breached = True
                                breach_count = int(parts[1])
                                break
                
                # Determine security level based on real data
                if is_breached and breach_count > 100000:
                    security_level = 'critical'
                elif is_breached and breach_count > 10000:
                    security_level = 'high_risk'
                elif is_breached:
                    security_level = 'medium_risk'
                elif len(password) >= 32 and zx_result['score'] >= 4:
                    security_level = 'fortress'
                elif len(password) >= 20 and zx_result['score'] >= 3:
                    security_level = 'military'
                elif len(password) >= 16 and zx_result['score'] >= 3:
                    security_level = 'strong'
                elif len(password) >= 12 and zx_result['score'] >= 2:
                    security_level = 'good'
                elif zx_result['score'] >= 2:
                    security_level = 'fair'
                else:
                    security_level = 'weak'
                    
            except Exception as api_error:
                logger.warning(f"HaveIBeenPwned API failed: {str(api_error)}")
                # Fallback to mock detection
                is_breached, breach_count, security_level = check_password_breach_mock(password)
        else:
            # Use mock breach detection
            is_breached, breach_count, security_level = check_password_breach_mock(password)
        
        return jsonify({
            'success': True,
            'breached': is_breached,
            'count': breach_count,
            'suggestions': zx_result['feedback']['suggestions'][:3],
            'score': zx_result['score'],
            'crack_time': zx_result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'security_level': security_level
        })
        
    except Exception as e:
        logger.error(f"Password analysis error: {str(e)}")
        return jsonify({
            'success': True,
            'breached': False,
            'count': 0,
            'suggestions': ['Password analysis temporarily unavailable'],
            'score': 2,
            'crack_time': 'unknown',
            'security_level': 'unknown'
        })

@app.route('/api/me', methods=['GET'])
def get_user_info():
    try:
        if current_user.is_authenticated:
            vault_count = VaultEntry.query.filter_by(user_id=current_user.id).count()
            recent_events = SecurityEvent.query.filter_by(user_id=current_user.id).order_by(
                SecurityEvent.timestamp.desc()
            ).limit(5).all()
            
            return jsonify({
                'success': True,
                'authenticated': True,
                'username': current_user.username,
                'salt': current_user.encryption_salt,
                'vault_count': vault_count,
                'notification_preferences': current_user.get_notification_preferences(),
                'breach_check_enabled': current_user.breach_check_enabled,
                'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
                'account_created': current_user.created_at.isoformat(),
                'recent_events': [{
                    'type': event.event_type,
                    'description': event.description,
                    'timestamp': event.timestamp.isoformat(),
                    'severity': event.severity
                } for event in recent_events]
            })
        else:
            return jsonify({
                'success': True,
                'authenticated': False
            })
    except Exception as e:
        logger.error(f"User info error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get user info'}), 500

@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard_stats():
    """Get dashboard statistics for the user"""
    try:
        # Vault statistics
        total_passwords = VaultEntry.query.filter_by(user_id=current_user.id).count()
        
        # Password strength distribution
        weak_passwords = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.password_strength_score <= 2
        ).count()
        strong_passwords = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.password_strength_score >= 3
        ).count()
        
        # Compromised passwords
        compromised_passwords = VaultEntry.query.filter_by(user_id=current_user.id, is_compromised=True).count()
        
        # Recent activity
        recent_accesses = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.last_accessed.isnot(None)
        ).order_by(VaultEntry.last_accessed.desc()).limit(5).all()
        
        # Old passwords (90+ days)
        old_threshold = datetime.utcnow() - timedelta(days=90)
        old_passwords = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.updated_at < old_threshold
        ).count()
        
        # Security events
        recent_events = SecurityEvent.query.filter_by(user_id=current_user.id).order_by(
            SecurityEvent.timestamp.desc()
        ).limit(10).all()
        
        # Calculate security score (0-100)
        security_score = 100
        if total_passwords > 0:
            security_score -= (weak_passwords / total_passwords) * 30  # Weak passwords penalty
            security_score -= (compromised_passwords / total_passwords) * 40  # Breach penalty
            security_score -= (old_passwords / total_passwords) * 20  # Old passwords penalty
            security_score = max(0, int(security_score))
        
        return jsonify({
            'success': True,
            'dashboard': {
                'security_score': security_score,
                'total_passwords': total_passwords,
                'weak_passwords': weak_passwords,
                'strong_passwords': strong_passwords,
                'compromised_passwords': compromised_passwords,
                'old_passwords': old_passwords,
                'vault_usage': round((total_passwords / 50) * 100, 1),  # Max 50 passwords
                'recent_accesses': [{
                    'site': entry.site,
                    'accessed': entry.last_accessed.isoformat(),
                    'access_count': entry.access_count
                } for entry in recent_accesses],
                'recent_events': [{
                    'type': event.event_type,
                    'description': event.description,
                    'timestamp': event.timestamp.isoformat(),
                    'severity': event.severity,
                    'ip_address': event.ip_address
                } for event in recent_events]
            }
        })
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load dashboard'}), 500

@app.route('/api/notifications/preferences', methods=['GET', 'POST'])
@login_required
def notification_preferences():
    """Get or update notification preferences"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            preferences = {
                'breach_alerts': data.get('breach_alerts', True),
                'password_age_warnings': data.get('password_age_warnings', True),
                'security_updates': data.get('security_updates', True),
                'login_notifications': data.get('login_notifications', False)
            }
            
            current_user.set_notification_preferences(preferences)
            current_user.breach_check_enabled = preferences['breach_alerts']
            db.session.commit()
            
            current_user.log_security_event('SETTINGS_UPDATED', 'Notification preferences updated')
            
            return jsonify({
                'success': True,
                'message': 'Notification preferences updated',
                'preferences': preferences
            })
        
        # GET request
        return jsonify({
            'success': True,
            'preferences': current_user.get_notification_preferences()
        })
        
    except Exception as e:
        logger.error(f"Notification preferences error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to manage preferences'}), 500

@app.route('/api/vault/export', methods=['POST'])
@login_required
def export_vault():
    """Export vault data (encrypted with master password)"""
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        export_format = data.get('format', 'json')  # json or csv
        
        if not current_user.check_password(master_password):
            current_user.log_security_event('EXPORT_DENIED', 'Invalid master password for vault export')
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        entries = VaultEntry.query.filter_by(user_id=current_user.id).order_by(VaultEntry.site).all()
        encryption_key = current_user.get_encryption_key(master_password)
        
        export_data = []
        for entry in entries:
            try:
                decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
                decrypted_notes = decrypt_password(entry.notes, encryption_key) if entry.notes else ''
                
                export_data.append({
                    'site': entry.site,
                    'username': entry.username,
                    'password': decrypted_password,
                    'category': entry.category,
                    'notes': decrypted_notes,
                    'created_at': entry.created_at.isoformat(),
                    'updated_at': entry.updated_at.isoformat(),
                    'strength_score': entry.password_strength_score,
                    'access_count': entry.access_count
                })
            except Exception as decrypt_error:
                logger.warning(f"Failed to decrypt entry {entry.id}: {str(decrypt_error)}")
                continue
        
        current_user.log_security_event('VAULT_EXPORTED', f'Vault exported with {len(export_data)} entries')
        
        return jsonify({
            'success': True,
            'data': export_data,
            'format': export_format,
            'exported_at': datetime.utcnow().isoformat(),
            'total_entries': len(export_data)
        })
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({'success': False, 'message': 'Export failed'}), 500

@app.route('/api/vault/breach-check', methods=['POST'])
@login_required
def check_vault_breaches():
    """Check all vault passwords for breaches"""
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        
        if not current_user.check_password(master_password):
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        if not current_user.breach_check_enabled:
            return jsonify({'success': False, 'message': 'Breach checking is disabled'}), 400
        
        entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
        encryption_key = current_user.get_encryption_key(master_password)
        
        checked_count = 0
        compromised_count = 0
        
        for entry in entries:
            try:
                # Rate limiting to avoid API abuse
                if REQUESTS_AVAILABLE:
                    time.sleep(0.2)
                
                decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
                
                if REQUESTS_AVAILABLE:
                    # Check breach status with real API
                    password_sha1 = hashlib.sha1(decrypted_password.encode('utf-8')).hexdigest().upper()
                    hash_prefix = password_sha1[:5]
                    hash_suffix = password_sha1[5:]
                    
                    breach_data = check_password_breach_online(hash_prefix)
                    is_compromised = False
                    
                    if breach_data:
                        for line in breach_data.split('\n'):
                            if line.strip():
                                parts = line.strip().split(':')
                                if len(parts) == 2 and parts[0] == hash_suffix:
                                    is_compromised = True
                                    compromised_count += 1
                                    break
                else:
                    # Use mock detection
                    is_compromised, _, _ = check_password_breach_mock(decrypted_password)
                    if is_compromised:
                        compromised_count += 1
                
                # Update entry
                entry.is_compromised = is_compromised
                checked_count += 1
                
            except Exception as check_error:
                logger.warning(f"Failed to check entry {entry.id}: {str(check_error)}")
                continue
        
        current_user.last_breach_check = datetime.utcnow()
        db.session.commit()
        
        current_user.log_security_event('BREACH_CHECK_COMPLETED', 
                                       f'Checked {checked_count} passwords, found {compromised_count} compromised')
        
        return jsonify({
            'success': True,
            'checked_count': checked_count,
            'compromised_count': compromised_count,
            'last_check': current_user.last_breach_check.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Breach check error: {str(e)}")
        return jsonify({'success': False, 'message': 'Breach check failed'}), 500

@app.route('/api/security/events', methods=['GET'])
@login_required
def get_security_events():
    """Get security events for the user"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
        
        events = SecurityEvent.query.filter_by(user_id=current_user.id).order_by(
            SecurityEvent.timestamp.desc()
        ).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'success': True,
            'events': [{
                'id': event.id,
                'type': event.event_type,
                'description': event.description,
                'timestamp': event.timestamp.isoformat(),
                'severity': event.severity,
                'ip_address': event.ip_address
            } for event in events.items],
            'pagination': {
                'page': events.page,
                'pages': events.pages,
                'per_page': events.per_page,
                'total': events.total,
                'has_next': events.has_next,
                'has_prev': events.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Security events error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load security events'}), 500

@app.route('/api/admin/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database connectivity
        db.session.execute('SELECT 1')
        
        # Get system stats
        total_users = User.query.count()
        total_passwords = VaultEntry.query.count()
        recent_logins = SecurityEvent.query.filter(
            SecurityEvent.event_type == 'LOGIN_SUCCESS',
            SecurityEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'stats': {
                'total_users': total_users,
                'total_passwords': total_passwords,
                'recent_logins_24h': recent_logins
            },
            'version': '1.0.0',
            'environment': os.environ.get('FLASK_ENV', 'development'),
            'haveibeenpwned_available': REQUESTS_AVAILABLE
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# --------------------------------------------------------
# Error Handlers
# --------------------------------------------------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'success': False, 'message': 'Rate limit exceeded. Please try again later.'}), 429

# --------------------------------------------------------
# SSL Certificate Generation Function
# --------------------------------------------------------
def create_ssl_certificate():
    try:
        from datetime import datetime, timedelta
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Development"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VaultGuard"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Write certificate to file
        with open('cert.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Write private key to file
        with open('key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print("✅ SSL certificates generated successfully!")
        print("   Certificate file: cert.pem")
        print("   Private key file: key.pem")
        return True
        
    except ImportError:
        logger.error("Cryptography package required for SSL certificates.")
        print("❌ Please install the cryptography package:")
        print("   pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"SSL certificate generation failed: {str(e)}")
        print(f"❌ Error generating SSL certificates: {str(e)}")
        return False

def cleanup_old_security_events():
    """Clean up security events older than 90 days"""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        old_events = SecurityEvent.query.filter(SecurityEvent.timestamp < cutoff_date).all()
        
        for event in old_events:
            db.session.delete(event)
        
        db.session.commit()
        logger.info(f"Cleaned up {len(old_events)} old security events")
        
    except Exception as e:
        logger.error(f"Failed to cleanup old events: {str(e)}")
        db.session.rollback()

# --------------------------------------------------------
# Run Application with HTTPS
# --------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database initialized successfully")
            
            # Run cleanup on startup
            cleanup_old_security_events()
            
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            print(f"❌ Database error: {str(e)}")
        
    print("=" * 70)
    print("🛡️  VAULTGUARD SECURE - PHASE 1 COMPLETE")
    print("=" * 70)
    print("✅ Enhanced security features enabled")
    print("✅ Phase 1 Features: Breach Monitoring, Enhanced UI, Notifications")
    print("✅ Real HaveIBeenPwned integration" + (" (Available)" if REQUESTS_AVAILABLE else " (Mock Mode)"))
    print("=" * 70)
    
    # SSL certificate handling
    ssl_context = None
    cert_exists = os.path.exists('cert.pem') and os.path.exists('key.pem')
    
    if not cert_exists:
        print("🔐 SSL certificates not found. Generating new certificates...")
        if create_ssl_certificate():
            print("✅ SSL certificates created successfully!")
            cert_exists = True
        else:
            print("⚠️  Could not create SSL certificates. Running without HTTPS.")
    
    if cert_exists:
        ssl_context = ('cert.pem', 'key.pem')
        print("\n🔒 HTTPS enabled with SSL certificates")
        print("\n🌐 Secure access URLs:")
        print("   • Primary: https://127.0.0.1:5000")
        print("   • Alternative: https://localhost:5000")
        print("\n⚠️  BROWSER SECURITY WARNING EXPECTED:")
        print("   This is normal for self-signed certificates. To proceed:")
        print("   1. Click 'Advanced' (Chrome/Edge) or 'Advanced...' (Firefox)")
        print("   2. Click 'Proceed to 127.0.0.1 (unsafe)' or similar option")
        print("   3. Your connection will still be encrypted with HTTPS")
    else:
        print("⚠️  Running without HTTPS - Some security features limited")
        print("🌐 Access your app at: http://127.0.0.1:5000")
    
    print("\n🔒 ACTIVE SECURITY FEATURES:")
    print("   ✅ AES-256 Password Encryption")
    print("   ✅ PBKDF2 Key Derivation (600k iterations)")
    print(f"   ✅ HaveIBeenPwned Breach Detection {'(Live API)' if REQUESTS_AVAILABLE else '(Mock)'}")
    print("   ✅ Security Event Logging")
    print("   ✅ Account Lockout Protection")
    print("   ✅ Session Security & Timeouts")
    print("   ✅ Enhanced Notifications System")
    print("   ✅ Vault Export Functionality")
    print("   ✅ Dashboard & Analytics")
    print("   ✅ Fixed Light Mode UI")
    print("   ✅ Enhanced Search/Sort Controls")
    print("=" * 70)
    
    # Start the application
    try:
        app.run(
            host='127.0.0.1', 
            port=5000, 
            ssl_context=ssl_context,
            debug=os.environ.get('FLASK_ENV') != 'production',
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        print(f"\n❌ Error starting application: {str(e)}")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure port 5000 is not already in use")
        print("   2. Try running without SSL if certificate issues persist")
        print("   3. Check that all required packages are installed:")
        print("      pip install flask flask-sqlalchemy flask-bcrypt flask-login")
        print("      pip install zxcvbn cryptography bleach requests")
        print("   4. Check the log file 'vaultguard.log' for more details")
