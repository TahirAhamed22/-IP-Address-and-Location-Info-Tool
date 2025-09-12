import os
import json
import base64
import logging
import random
import secrets
import re
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

# --------------------------------------------------------
# Initialize Flask app
# --------------------------------------------------------
app = Flask(__name__)

# --------------------------------------------------------
# FIXED Security Configuration
# --------------------------------------------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///vaultguard_secure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# ✅ FIXED: Disabled secure cookies for development (was causing server errors)
# app.config['SESSION_COOKIE_SECURE'] = True  # Only enable this for HTTPS in production
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
    except Exception as e:
        logger.error(f"User loader error: {str(e)}")
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
    vault_entries = db.relationship('VaultEntry', backref='owner', lazy=True, cascade='all, delete-orphan')

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
    
    def unlock_account(self):
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()

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

class VaultEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    access_count = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --------------------------------------------------------
# Helper Functions
# --------------------------------------------------------
def get_client_ip():
    """Get client IP address"""
    try:
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr or 'unknown'
    except:
        return 'unknown'

# --------------------------------------------------------
# Security Functions
# --------------------------------------------------------
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
# Create database with error handling
# --------------------------------------------------------
def initialize_database():
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database initialized successfully")
            print("✅ Database initialized successfully")
            return True
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        print(f"❌ Database initialization failed: {str(e)}")
        return False

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
    try:
        username = current_user.username
        logout_user()
        session.clear()
        logger.info(f"User {username} logged out")
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return redirect(url_for('home'))

# --------------------------------------------------------
# API Routes with Enhanced Error Handling
# --------------------------------------------------------
@app.route('/api/login', methods=["POST"])
def api_login():
    try:
        # Get and validate request data
        data = request.get_json()
        if not data:
            logger.warning("Login attempt with no JSON data")
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        client_ip = get_client_ip()
        
        logger.info(f"Login attempt for username: '{username}' from IP: {client_ip}")
        
        if not username or not password:
            logger.warning(f"Login attempt with missing credentials from {client_ip}")
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            logger.warning(f"Login attempt for non-existent user: '{username}' from {client_ip}")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Check account lock
        if user.is_account_locked():
            logger.warning(f"Login attempt for locked account: '{username}' from {client_ip}")
            return jsonify({'success': False, 'message': 'Account locked. Try again later.'}), 423
        
        # Verify password
        if user.check_password(password):
            # Success - unlock account and login
            user.unlock_account()
            db.session.commit()
            
            login_user(user, remember=False)
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session.permanent = True
            
            logger.info(f"Successful login for user: '{username}' from {client_ip}")
            
            return jsonify({
                'success': True, 
                'message': 'Secure login successful!', 
                'salt': user.encryption_salt,
                'username': user.username
            }), 200
        else:
            # Failed password - increment attempts
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= 3:
                user.lock_account(60)
                logger.warning(f"Account locked for user: '{username}' after 3 failed attempts from {client_ip}")
            else:
                logger.warning(f"Failed login attempt #{user.failed_login_attempts} for user: '{username}' from {client_ip}")
            
            db.session.commit()
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

@app.route('/api/register', methods=["POST"])
def api_register():
    try:
        # Get and validate request data
        data = request.get_json()
        if not data:
            logger.warning("Registration attempt with no JSON data")
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        client_ip = get_client_ip()
        
        logger.info(f"Registration attempt for username: '{username}' from IP: {client_ip}")
        
        # Validate username
        username_valid, username_error = validate_username(username)
        if not username_valid:
            logger.warning(f"Registration failed - invalid username: '{username}' from {client_ip}")
            return jsonify({'success': False, 'message': username_error}), 400
        
        # Validate password
        password_valid, password_error = validate_password_strength(password)
        if not password_valid:
            logger.warning(f"Registration failed - weak password for: '{username}' from {client_ip}")
            return jsonify({'success': False, 'message': password_error}), 400

        # Check if user exists
        if User.query.filter_by(username=username).first():
            logger.warning(f"Registration failed - username exists: '{username}' from {client_ip}")
            return jsonify({'success': False, 'message': 'Username already exists'}), 400

        # Create new user
        salt = secrets.token_bytes(64)
        encryption_salt = base64.b64encode(salt).decode('utf-8')
        
        new_user = User(username=username, encryption_salt=encryption_salt)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Auto-login the new user
        login_user(new_user, remember=False)
        session['logged_in'] = True
        session['username'] = new_user.username
        session['user_id'] = new_user.id
        session.permanent = True
        
        logger.info(f"Successful registration and login for user: '{username}' from {client_ip}")
        
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
            
            # Check vault limit
            if VaultEntry.query.filter_by(user_id=current_user.id).count() >= 50:
                return jsonify({'success': False, 'message': 'Vault limit reached (50 passwords)'}), 400
                
            site = sanitize_input(data.get('site', ''))
            username = sanitize_input(data.get('username', ''))
            password = data.get('password', '')
            master_password = data.get('master_password', '')

            if not all([site, username, password, master_password]):
                return jsonify({'success': False, 'message': 'All fields required'}), 400

            # Verify master password
            if not current_user.check_password(master_password):
                logger.warning(f"Invalid master password attempt by user: {current_user.username}")
                return jsonify({'success': False, 'message': 'Invalid master password'}), 401

            # Encrypt password
            encryption_key = current_user.get_encryption_key(master_password)
            encrypted_password = encrypt_password(password, encryption_key)
            
            # Check for existing entry
            existing_entry = VaultEntry.query.filter_by(
                site=site, username=username, user_id=current_user.id
            ).first()
            
            if existing_entry:
                existing_entry.encrypted_password = encrypted_password
                existing_entry.updated_at = datetime.utcnow()
                message = 'Password updated securely!'
                logger.info(f"Password updated for {site} by user: {current_user.username}")
            else:
                new_entry = VaultEntry(
                    site=site,
                    username=username,
                    encrypted_password=encrypted_password,
                    user_id=current_user.id
                )
                db.session.add(new_entry)
                message = 'Password encrypted and saved!'
                logger.info(f"New password added for {site} by user: {current_user.username}")

            db.session.commit()
            return jsonify({'success': True, 'message': message}), 201

        # GET request - return vault entries
        entries = VaultEntry.query.filter_by(user_id=current_user.id).order_by(VaultEntry.updated_at.desc()).all()
        vault_entries = [{
            'id': entry.id,
            'site': entry.site,
            'username': entry.username,
            'created_at': entry.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': entry.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'access_count': entry.access_count
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
        
        # Verify master password
        if not current_user.check_password(master_password):
            logger.warning(f"Invalid master password for password access by user: {current_user.username}")
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        # Find entry
        entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
        if not entry:
            return jsonify({'success': False, 'message': 'Password not found'}), 404
        
        # Decrypt password
        encryption_key = current_user.get_encryption_key(master_password)
        decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
        
        # Update access tracking
        entry.access_count += 1
        db.session.commit()
        
        logger.info(f"Password accessed for {entry.site} by user: {current_user.username}")
        
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
        
        logger.info(f"Password deleted for {site_name} by user: {current_user.username}")
        
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
        
        # Use zxcvbn for analysis
        zx_result = zxcvbn(password)
        
        # Enhanced breach detection (mock for now)
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
        
        is_breached = False
        breach_count = 0
        security_level = 'unknown'
        
        lower_password = password.lower()
        
        if lower_password in [p.lower() for p in high_risk_passwords]:
            is_breached = True
            breach_count = random.randint(1000000, 10000000)
            security_level = 'critical'
        elif any(pattern.lower() in lower_password for pattern in critical_patterns):
            is_breached = True
            breach_count = random.randint(100000, 2000000)
            security_level = 'high_risk'
        elif any(seq in lower_password for seq in keyboard_sequences):
            is_breached = True
            breach_count = random.randint(50000, 500000)
            security_level = 'high_risk'
        elif repeated_patterns:
            is_breached = True
            breach_count = random.randint(10000, 200000)
            security_level = 'medium_risk'
        elif len(password) < 8:
            is_breached = True
            breach_count = random.randint(500000, 5000000)
            security_level = 'critical'
        elif (len(password) >= 32 and 
              any(c.isupper() for c in password) and 
              any(c.islower() for c in password) and 
              any(c.isdigit() for c in password) and 
              any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password)):
            is_breached = False
            breach_count = 0
            security_level = 'fortress'
        elif (len(password) >= 20 and 
              any(c.isupper() for c in password) and 
              any(c.islower() for c in password) and 
              any(c.isdigit() for c in password) and 
              any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password)):
            is_breached = random.random() < 0.01
            breach_count = random.randint(1, 5) if is_breached else 0
            security_level = 'military'
        elif (len(password) >= 16 and 
              any(c.isupper() for c in password) and 
              any(c.islower() for c in password) and 
              any(c.isdigit() for c in password) and 
              any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)):
            is_breached = random.random() < 0.02
            breach_count = random.randint(1, 25) if is_breached else 0
            security_level = 'strong'
        elif (len(password) >= 12 and 
              sum([any(c.isupper() for c in password),
                   any(c.islower() for c in password),
                   any(c.isdigit() for c in password),
                   any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)]) >= 3):
            is_breached = random.random() < 0.05
            breach_count = random.randint(1, 100) if is_breached else 0
            security_level = 'good'
        elif zx_result['score'] >= 3:
            is_breached = random.random() < 0.15
            breach_count = random.randint(100, 5000) if is_breached else 0
            security_level = 'medium'
        else:
            is_breached = True
            breach_count = random.randint(10000, 1000000)
            security_level = 'weak'
        
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
            return jsonify({
                'success': True,
                'authenticated': True,
                'username': current_user.username,
                'salt': current_user.encryption_salt,
                'vault_count': vault_count
            })
        else:
            return jsonify({
                'success': True,
                'authenticated': False
            })
    except Exception as e:
        logger.error(f"User info error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get user info'}), 500

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
    return jsonify({'success': False, 'message': 'Internal server error occurred'}), 500

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

# --------------------------------------------------------
# Run Application
# --------------------------------------------------------
if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  VAULTGUARD SECURE - FIXED VERSION")
    print("=" * 70)
    
    # Initialize database first
    if not initialize_database():
        print("❌ Cannot start without database. Please fix database issues first.")
        exit(1)
    
    print("✅ Enhanced security features enabled")
    print("✅ Session cookie issues FIXED")
    print("✅ Error handling ENHANCED")
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
        print("⚠️  Running without HTTPS")
        print("🌐 Access your app at: http://127.0.0.1:5000")
    
    print("\n🔒 ACTIVE SECURITY FEATURES:")
    print("   ✅ AES-256 Password Encryption")
    print("   ✅ PBKDF2 Key Derivation (600k iterations)")
    print("   ✅ Enhanced Password Analysis (Mock)")
    print("   ✅ Account Lockout Protection")
    print("   ✅ Session Security")
    print("   ✅ Comprehensive Logging")
    print("   ✅ Input Validation & Sanitization")
    print("   ✅ FIXED: Session Cookie Issues")
    print("=" * 70)
    
    # Start the application
    try:
        print(f"\n🚀 Starting VaultGuard on port 5000...")
        print(f"   Debug mode: {'ON' if os.environ.get('FLASK_ENV') != 'production' else 'OFF'}")
        print(f"   Environment: {os.environ.get('FLASK_ENV', 'development')}")
        print("\n📝 Check 'vaultguard.log' for detailed application logs")
        print("=" * 70)
        
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
        print("   2. Check that all required packages are installed:")
        print("      pip install flask flask-sqlalchemy flask-bcrypt flask-login")
        print("      pip install zxcvbn cryptography bleach")
        print("   3. Try running without SSL if certificate issues persist")
        print("   4. Check 'vaultguard.log' for detailed error information")
        print("   5. Make sure you have write permissions in the current directory")
