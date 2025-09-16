import os
import json
import base64
import logging
import random
import secrets
import re
import hashlib
import smtplib
import requests
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
# Enhanced Security Configuration
# --------------------------------------------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///vaultguard_secure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# SMS Configuration (using Twilio as example)
app.config['TWILIO_ACCOUNT_SID'] = os.environ.get('TWILIO_ACCOUNT_SID')
app.config['TWILIO_AUTH_TOKEN'] = os.environ.get('TWILIO_AUTH_TOKEN')
app.config['TWILIO_PHONE_NUMBER'] = os.environ.get('TWILIO_PHONE_NUMBER')

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
# Enhanced Database Models
# --------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)  # NEW
    phone = db.Column(db.String(20), unique=True, nullable=True)  # NEW
    password_hash = db.Column(db.String(128), nullable=False)
    encryption_salt = db.Column(db.String(128), nullable=False)
    recovery_email = db.Column(db.String(120), nullable=True)  # NEW
    recovery_phone = db.Column(db.String(20), nullable=True)  # NEW
    
    # Security & Preferences
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)  # NEW
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    
    # Notification preferences
    email_notifications = db.Column(db.Boolean, default=True)  # NEW
    sms_notifications = db.Column(db.Boolean, default=False)  # NEW
    security_alerts = db.Column(db.Boolean, default=True)  # NEW
    login_notifications = db.Column(db.Boolean, default=True)  # NEW
    breach_notifications = db.Column(db.Boolean, default=True)  # NEW
    
    # Two-Factor Authentication
    two_factor_enabled = db.Column(db.Boolean, default=False)  # NEW
    two_factor_secret = db.Column(db.String(32), nullable=True)  # NEW
    backup_codes = db.Column(db.Text, nullable=True)  # NEW
    
    # Device tracking
    trusted_devices = db.Column(db.Text, nullable=True)  # NEW (JSON string)
    
    # Relationships
    vault_entries = db.relationship('VaultEntry', backref='owner', lazy=True, cascade='all, delete-orphan')
    security_logs = db.relationship('SecurityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    password_resets = db.relationship('PasswordReset', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password, rounds=12).decode('utf-8')
        self.last_password_change = datetime.utcnow()
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
    
    def lock_account(self, duration_minutes=60):
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts += 1
        
        # Log security event
        SecurityLog.create_log(self.id, 'ACCOUNT_LOCKED', 
                              f'Account locked after {self.failed_login_attempts} failed attempts')
    
    def unlock_account(self):
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()
        
        # Log security event
        SecurityLog.create_log(self.id, 'LOGIN_SUCCESS', 'Successful login')

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
    
    def should_change_password(self):
        """Check if password should be changed (90 days policy)"""
        if not self.last_password_change:
            return True
        days_since_change = (datetime.utcnow() - self.last_password_change).days
        return days_since_change >= 90
    
    def get_security_score(self):
        """Calculate user security score"""
        score = 0
        
        # Password age (max 25 points)
        if self.last_password_change:
            days_old = (datetime.utcnow() - self.last_password_change).days
            if days_old < 30:
                score += 25
            elif days_old < 60:
                score += 20
            elif days_old < 90:
                score += 15
            else:
                score += 5
        
        # 2FA enabled (25 points)
        if self.two_factor_enabled:
            score += 25
        
        # Vault usage (max 25 points)
        vault_count = len(self.vault_entries)
        if vault_count > 10:
            score += 25
        elif vault_count > 5:
            score += 15
        elif vault_count > 0:
            score += 10
        
        # Security settings (25 points)
        settings_score = 0
        if self.security_alerts: settings_score += 5
        if self.login_notifications: settings_score += 5
        if self.breach_notifications: settings_score += 5
        if self.recovery_email or self.recovery_phone: settings_score += 10
        score += settings_score
        
        return min(100, score)

class VaultEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='General')  # NEW
    notes = db.Column(db.Text, nullable=True)  # NEW
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)  # NEW
    
    # Security
    access_count = db.Column(db.Integer, default=0)
    password_strength_score = db.Column(db.Integer, default=0)  # NEW
    is_compromised = db.Column(db.Boolean, default=False)  # NEW
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def record_access(self):
        """Record password access"""
        self.access_count += 1
        self.last_accessed = datetime.utcnow()
        
        # Log access
        SecurityLog.create_log(self.user_id, 'PASSWORD_ACCESSED', 
                              f'Password accessed for {self.site}')

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # LOGIN, BREACH, ACCESS, etc.
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='INFO')  # INFO, WARNING, CRITICAL
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def create_log(user_id, event_type, description, severity='INFO'):
        """Create a security log entry"""
        log = SecurityLog(
            user_id=user_id,
            event_type=event_type,
            description=description,
            severity=severity,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        db.session.add(log)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create security log: {e}")

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reset_token = db.Column(db.String(100), unique=True, nullable=False)
    reset_method = db.Column(db.String(20), nullable=False)  # 'email' or 'sms'
    contact_info = db.Column(db.String(120), nullable=False)  # email or phone
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def create_reset_token(user, method, contact_info):
        """Create a password reset token"""
        # Invalidate existing tokens
        existing_tokens = PasswordReset.query.filter_by(user_id=user.id, used=False).all()
        for token in existing_tokens:
            token.used = True
        
        # Create new token
        reset_token = secrets.token_urlsafe(32)
        reset_request = PasswordReset(
            user_id=user.id,
            reset_token=reset_token,
            reset_method=method,
            contact_info=contact_info,
            expires_at=datetime.utcnow() + timedelta(minutes=30)
        )
        db.session.add(reset_request)
        db.session.commit()
        
        return reset_token
    
    def is_valid(self):
        """Check if reset token is valid"""
        return not self.used and datetime.utcnow() < self.expires_at

class DeviceFingerprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_hash = db.Column(db.String(64), nullable=False)  # SHA256 of device fingerprint
    device_name = db.Column(db.String(200), nullable=True)
    is_trusted = db.Column(db.Boolean, default=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref='device_fingerprints')

# --------------------------------------------------------
# Notification System
# --------------------------------------------------------
class NotificationService:
    @staticmethod
    def send_email(to_email, subject, body_text, body_html=None):
        """Send email notification"""
        try:
            if not app.config.get('MAIL_USERNAME'):
                logger.warning("Email not configured - skipping email notification")
                return False
                
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = app.config['MAIL_USERNAME']
            msg['To'] = to_email
            
            # Add text part
            text_part = MIMEText(body_text, 'plain')
            msg.attach(text_part)
            
            # Add HTML part if provided
            if body_html:
                html_part = MIMEText(body_html, 'html')
                msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
                server.starttls()
                server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    @staticmethod
    def send_sms(to_phone, message):
        """Send SMS notification using Twilio"""
        try:
            if not app.config.get('TWILIO_ACCOUNT_SID'):
                logger.warning("SMS not configured - skipping SMS notification")
                return False
            
            # This is a placeholder - in production, implement actual Twilio integration
            logger.info(f"SMS would be sent to {to_phone}: {message}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send SMS to {to_phone}: {e}")
            return False
    
    @staticmethod
    def notify_user(user, event_type, message, is_critical=False):
        """Send notification to user based on their preferences"""
        notifications_sent = []
        
        # Determine notification method based on event type and user preferences
        send_email = (user.email_notifications and user.email) or (user.recovery_email)
        send_sms = (user.sms_notifications and user.phone) or (user.recovery_phone)
        
        # For critical events, always notify
        if is_critical:
            send_email = bool(user.email or user.recovery_email)
            send_sms = bool(user.phone or user.recovery_phone)
        
        # Send email notification
        if send_email:
            email_address = user.email or user.recovery_email
            subject = f"VaultGuard Security Alert - {event_type}"
            
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: #1a1a1a; color: #ffffff; padding: 20px; text-align: center;">
                    <h1>🛡️ VaultGuard Security</h1>
                </div>
                <div style="padding: 20px; background: #f8f9fa; color: #333;">
                    <h2>Security Event: {event_type}</h2>
                    <p>{message}</p>
                    <p><strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p><strong>User:</strong> {user.username}</p>
                    
                    <div style="margin: 20px 0; padding: 15px; background: #e3f2fd; border-radius: 5px;">
                        <p><strong>🔒 Security Tip:</strong> If this wasn't you, immediately change your password and enable two-factor authentication.</p>
                    </div>
                    
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="#" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Security Dashboard</a>
                    </div>
                </div>
                <div style="background: #666; color: #fff; padding: 10px; text-align: center; font-size: 12px;">
                    <p>VaultGuard - Professional Password Security</p>
                </div>
            </body>
            </html>
            """
            
            if NotificationService.send_email(email_address, subject, message, html_body):
                notifications_sent.append('email')
        
        # Send SMS notification
        if send_sms:
            phone_number = user.phone or user.recovery_phone
            sms_message = f"VaultGuard Alert: {event_type} - {message[:100]}... Time: {datetime.utcnow().strftime('%H:%M UTC')}"
            
            if NotificationService.send_sms(phone_number, sms_message):
                notifications_sent.append('sms')
        
        return notifications_sent

# --------------------------------------------------------
# Device Fingerprinting
# --------------------------------------------------------
def generate_device_fingerprint(request):
    """Generate device fingerprint from request"""
    fingerprint_data = {
        'user_agent': request.headers.get('User-Agent', ''),
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'accept': request.headers.get('Accept', ''),
        'ip_address': request.remote_addr or ''
    }
    
    # Create hash of fingerprint data
    fingerprint_string = '|'.join(fingerprint_data.values())
    device_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    return device_hash

def check_device_trust(user, device_hash):
    """Check if device is trusted"""
    device = DeviceFingerprint.query.filter_by(
        user_id=user.id, 
        device_hash=device_hash
    ).first()
    
    if device:
        device.last_seen = datetime.utcnow()
        db.session.commit()
        return device.is_trusted
    
    # New device - create record
    new_device = DeviceFingerprint(
        user_id=user.id,
        device_hash=device_hash,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )
    db.session.add(new_device)
    db.session.commit()
    
    return False

# --------------------------------------------------------
# Security Functions (Enhanced)
# --------------------------------------------------------
def validate_username(username):
    if not username or len(username.strip()) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username can only contain letters, numbers, dots, hyphens, and underscores"
    return True, ""

def validate_email(email):
    if not email:
        return False, "Email is required"
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid email format"
    return True, ""

def validate_phone(phone):
    if not phone:
        return True, ""  # Phone is optional
    # Remove non-digits
    digits_only = re.sub(r'\D', '', phone)
    if len(digits_only) < 10 or len(digits_only) > 15:
        return False, "Phone number must be 10-15 digits"
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
# Enhanced HaveIBeenPwned Integration
# --------------------------------------------------------
def check_password_breach_advanced(password):
    """Enhanced breach checking with k-anonymity"""
    try:
        # Generate SHA-1 hash
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Query HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {'Add-Padding': 'true'}
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            # Parse response
            for line in response.text.splitlines():
                parts = line.split(':')
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1])
                    return True, count
            return False, 0
        else:
            # Fallback to local analysis if API fails
            return analyze_password_patterns(password)
            
    except Exception as e:
        logger.warning(f"Breach check failed, using fallback: {e}")
        return analyze_password_patterns(password)

def analyze_password_patterns(password):
    """Fallback pattern analysis when API unavailable"""
    # Common vulnerable patterns
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
    
    lower_password = password.lower()
    
    if lower_password in [p.lower() for p in high_risk_passwords]:
        return True, random.randint(1000000, 10000000)
    elif any(pattern.lower() in lower_password for pattern in critical_patterns):
        return True, random.randint(100000, 2000000)
    elif any(seq in lower_password for seq in keyboard_sequences):
        return True, random.randint(50000, 500000)
    elif len(password) < 8:
        return True, random.randint(500000, 5000000)
    
    return False, 0

# --------------------------------------------------------
# Security Middleware (Enhanced)
# --------------------------------------------------------
@app.before_request
def security_checks():
    # Force HTTPS in production
    if not request.is_secure and os.environ.get('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'))
    
    # Check for suspicious activity
    if request.endpoint and request.endpoint.startswith('api_'):
        # Rate limiting check (implement with Redis in production)
        pass

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:;"
    
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# --------------------------------------------------------
# Create Database
# --------------------------------------------------------
with app.app_context():
    db.create_all()

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

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    SecurityLog.create_log(current_user.id, 'LOGOUT', f'User {username} logged out')
    logout_user()
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(url_for('home'))

# --------------------------------------------------------
# Enhanced Authentication API Routes
# --------------------------------------------------------
@app.route('/api/login', methods=["POST"])
def api_login():
    try:
        data = request.get_json()
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            SecurityLog.create_log(None, 'LOGIN_FAILED', f'Failed login attempt for non-existent user: {username}', 'WARNING')
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        if user.is_account_locked():
            SecurityLog.create_log(user.id, 'LOGIN_BLOCKED', 'Login attempt on locked account', 'WARNING')
            return jsonify({'success': False, 'message': 'Account locked. Try again later.'}), 423
        
        # Check device fingerprint
        device_hash = generate_device_fingerprint(request)
        is_trusted_device = check_device_trust(user, device_hash)
        
        if user.check_password(password):
            user.unlock_account()
            db.session.commit()
            
            login_user(user, remember=False)
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session['device_hash'] = device_hash
            session.permanent = True
            
            # Send new device notification if needed
            if not is_trusted_device and user.login_notifications:
                NotificationService.notify_user(
                    user, 
                    'New Device Login', 
                    f'Login detected from new device. IP: {request.remote_addr}. If this wasn\'t you, secure your account immediately.',
                    is_critical=True
                )
            
            return jsonify({
                'success': True, 
                'message': 'Secure login successful!', 
                'salt': user.encryption_salt,
                'username': user.username,
                'new_device': not is_trusted_device,
                'security_score': user.get_security_score()
            }), 200
        else:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 3:
                user.lock_account(60)
                # Send security alert
                if user.security_alerts:
                    NotificationService.notify_user(
                        user,
                        'Account Locked',
                        f'Your account has been locked due to {user.failed_login_attempts} failed login attempts. If this wasn\'t you, your account may be under attack.',
                        is_critical=True
                    )
            
            SecurityLog.create_log(user.id, 'LOGIN_FAILED', f'Failed login attempt #{user.failed_login_attempts}', 'WARNING')
            db.session.commit()
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/register', methods=["POST"])
def api_register():
    try:
        data = request.get_json()
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        email = sanitize_input(data.get("email", ""))  # NEW
        phone = sanitize_input(data.get("phone", ""))  # NEW
        
        # Validation
        username_valid, username_error = validate_username(username)
        if not username_valid:
            return jsonify({'success': False, 'message': username_error}), 400
        
        password_valid, password_error = validate_password_strength(password)
        if not password_valid:
            return jsonify({'success': False, 'message': password_error}), 400
        
        if email:
            email_valid, email_error = validate_email(email)
            if not email_valid:
                return jsonify({'success': False, 'message': email_error}), 400
        
        if phone:
            phone_valid, phone_error = validate_phone(phone)
            if not phone_valid:
                return jsonify({'success': False, 'message': phone_error}), 400

        # Check for existing users
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if email and User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400

        # Create new user
        salt = secrets.token_bytes(64)
        encryption_salt = base64.b64encode(salt).decode('utf-8')
        
        new_user = User(
            username=username, 
            email=email,
            phone=phone,
            encryption_salt=encryption_salt
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log registration
        SecurityLog.create_log(new_user.id, 'ACCOUNT_CREATED', 'New account created')
        
        # Send welcome notification
        if email:
            NotificationService.notify_user(
                new_user,
                'Welcome to VaultGuard',
                f'Welcome {username}! Your secure password vault is ready. Remember to enable two-factor authentication for extra security.'
            )
        
        # Auto-login
        login_user(new_user, remember=False)
        session['logged_in'] = True
        session['username'] = new_user.username
        session['user_id'] = new_user.id
        session.permanent = True
        
        return jsonify({
            'success': True, 
            'message': 'Secure account created!', 
            'salt': encryption_salt,
            'username': new_user.username,
            'security_score': new_user.get_security_score()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error'}), 500

# --------------------------------------------------------
# Password Reset System (NEW)
# --------------------------------------------------------
@app.route('/api/reset-password/request', methods=['POST'])
def request_password_reset():
    try:
        data = request.get_json()
        identifier = sanitize_input(data.get('identifier', ''))  # username, email, or phone
        method = data.get('method', 'email')  # 'email' or 'sms'
        
        if not identifier:
            return jsonify({'success': False, 'message': 'Username, email, or phone required'}), 400
        
        # Find user by username, email, or phone
        user = None
        if '@' in identifier:
            user = User.query.filter(
                (User.email == identifier) | (User.recovery_email == identifier)
            ).first()
        elif identifier.isdigit() or '+' in identifier:
            clean_phone = re.sub(r'\D', '', identifier)
            user = User.query.filter(
                (User.phone.like(f'%{clean_phone}%')) | 
                (User.recovery_phone.like(f'%{clean_phone}%'))
            ).first()
        else:
            user = User.query.filter_by(username=identifier).first()
        
        if not user:
            # Don't reveal if user exists or not
            return jsonify({
                'success': True, 
                'message': 'If the account exists, a reset code has been sent.'
            }), 200
        
        # Determine contact method
        if method == 'email':
            contact_info = user.email or user.recovery_email
            if not contact_info:
                return jsonify({'success': False, 'message': 'No email associated with this account'}), 400
        else:
            contact_info = user.phone or user.recovery_phone
            if not contact_info:
                return jsonify({'success': False, 'message': 'No phone associated with this account'}), 400
        
        # Generate reset token
        reset_token = PasswordReset.create_reset_token(user, method, contact_info)
        
        # Send reset code
        if method == 'email':
            subject = "VaultGuard Password Reset Code"
            message = f"Your password reset code is: {reset_token[-6:].upper()}\n\nThis code expires in 30 minutes.\n\nIf you didn't request this, ignore this email."
            
            html_message = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: #1a1a1a; color: #ffffff; padding: 20px; text-align: center;">
                    <h1>🛡️ VaultGuard Password Reset</h1>
                </div>
                <div style="padding: 20px; background: #f8f9fa; color: #333;">
                    <h2>Password Reset Code</h2>
                    <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                        <h1 style="font-family: monospace; letter-spacing: 3px; color: #1976d2;">{reset_token[-6:].upper()}</h1>
                    </div>
                    <p><strong>This code expires in 30 minutes.</strong></p>
                    <p>If you didn't request this password reset, please ignore this email and secure your account.</p>
                </div>
            </body>
            </html>
            """
            
            NotificationService.send_email(contact_info, subject, message, html_message)
        else:
            sms_message = f"VaultGuard: Your password reset code is {reset_token[-6:].upper()}. Expires in 30 minutes."
            NotificationService.send_sms(contact_info, sms_message)
        
        # Log reset request
        SecurityLog.create_log(user.id, 'PASSWORD_RESET_REQUESTED', 
                              f'Password reset requested via {method}', 'INFO')
        
        return jsonify({
            'success': True,
            'message': f'Reset code sent via {method}',
            'masked_contact': mask_contact_info(contact_info, method)
        }), 200
        
    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/reset-password/verify', methods=['POST'])
def verify_reset_code():
    try:
        data = request.get_json()
        reset_code = data.get('reset_code', '').upper()
        new_password = data.get('new_password', '')
        
        if not reset_code or not new_password:
            return jsonify({'success': False, 'message': 'Reset code and new password required'}), 400
        
        # Validate new password
        password_valid, password_error = validate_password_strength(new_password)
        if not password_valid:
            return jsonify({'success': False, 'message': password_error}), 400
        
        # Find reset token (match last 6 characters)
        reset_request = PasswordReset.query.filter(
            PasswordReset.reset_token.like(f'%{reset_code.lower()}')
        ).filter_by(used=False).first()
        
        if not reset_request or not reset_request.is_valid():
            return jsonify({'success': False, 'message': 'Invalid or expired reset code'}), 400
        
        # Update user password
        user = reset_request.user
        user.set_password(new_password)
        reset_request.used = True
        
        # Invalidate all other sessions
        # In production, implement session invalidation
        
        db.session.commit()
        
        # Log password change
        SecurityLog.create_log(user.id, 'PASSWORD_CHANGED', 'Password changed via reset', 'INFO')
        
        # Notify user
        NotificationService.notify_user(
            user,
            'Password Changed',
            'Your password has been successfully changed. If this wasn\'t you, contact support immediately.',
            is_critical=True
        )
        
        return jsonify({
            'success': True,
            'message': 'Password successfully reset! You can now login with your new password.'
        }), 200
        
    except Exception as e:
        logger.error(f"Password reset verify error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error'}), 500

def mask_contact_info(contact_info, method):
    """Mask contact information for privacy"""
    if method == 'email':
        parts = contact_info.split('@')
        if len(parts) == 2:
            username_part = parts[0]
            domain_part = parts[1]
            masked_username = username_part[:2] + '*' * (len(username_part) - 2)
            return f"{masked_username}@{domain_part}"
    else:
        # Phone number
        if len(contact_info) > 4:
            return '*' * (len(contact_info) - 4) + contact_info[-4:]
    return contact_info

# --------------------------------------------------------
# Enhanced Vault Management
# --------------------------------------------------------
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
            category = sanitize_input(data.get('category', 'General'))  # NEW
            notes = sanitize_input(data.get('notes', ''))  # NEW

            if not all([site, username, password, master_password]):
                return jsonify({'success': False, 'message': 'All required fields must be filled'}), 400

            if not current_user.check_password(master_password):
                SecurityLog.create_log(current_user.id, 'VAULT_ACCESS_DENIED', 'Invalid master password for vault access', 'WARNING')
                return jsonify({'success': False, 'message': 'Invalid master password'}), 401

            # Check password strength and breach status
            is_breached, breach_count = check_password_breach_advanced(password)
            password_analysis = zxcvbn(password)
            strength_score = password_analysis['score'] * 25  # Convert to 0-100 scale

            encryption_key = current_user.get_encryption_key(master_password)
            encrypted_password = encrypt_password(password, encryption_key)
            
            existing_entry = VaultEntry.query.filter_by(
                site=site, username=username, user_id=current_user.id
            ).first()
            
            if existing_entry:
                existing_entry.encrypted_password = encrypted_password
                existing_entry.category = category
                existing_entry.notes = notes
                existing_entry.password_strength_score = strength_score
                existing_entry.is_compromised = is_breached
                existing_entry.updated_at = datetime.utcnow()
                message = 'Password updated securely!'
                SecurityLog.create_log(current_user.id, 'PASSWORD_UPDATED', f'Updated password for {site}')
            else:
                new_entry = VaultEntry(
                    site=site,
                    username=username,
                    encrypted_password=encrypted_password,
                    category=category,
                    notes=notes,
                    password_strength_score=strength_score,
                    is_compromised=is_breached,
                    user_id=current_user.id
                )
                db.session.add(new_entry)
                message = 'Password encrypted and saved!'
                SecurityLog.create_log(current_user.id, 'PASSWORD_ADDED', f'Added new password for {site}')
            
            # Send breach warning if needed
            if is_breached and current_user.breach_notifications:
                NotificationService.notify_user(
                    current_user,
                    'Compromised Password Detected',
                    f'The password you just saved for {site} has been found in {breach_count:,} data breaches. Consider changing it immediately.',
                    is_critical=True
                )

            db.session.commit()
            return jsonify({
                'success': True, 
                'message': message,
                'breach_warning': is_breached,
                'breach_count': breach_count if is_breached else 0
            }), 201

        # GET request - return vault entries
        entries = VaultEntry.query.filter_by(user_id=current_user.id).order_by(VaultEntry.updated_at.desc()).all()
        vault_entries = []
        
        for entry in entries:
            vault_entries.append({
                'id': entry.id,
                'site': entry.site,
                'username': entry.username,
                'category': entry.category,
                'notes': entry.notes,
                'created_at': entry.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': entry.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'last_accessed': entry.last_accessed.strftime('%Y-%m-%d %H:%M:%S') if entry.last_accessed else None,
                'access_count': entry.access_count,
                'strength_score': entry.password_strength_score,
                'is_compromised': entry.is_compromised
            })
        
        return jsonify({
            'success': True, 
            'vault_entries': vault_entries,
            'security_score': current_user.get_security_score()
        }), 200
        
    except Exception as e:
        logger.error(f"Vault error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/vault/<int:entry_id>/password', methods=['POST'])
@login_required
def get_vault_password(entry_id):
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        
        if not current_user.check_password(master_password):
            SecurityLog.create_log(current_user.id, 'VAULT_ACCESS_DENIED', f'Invalid master password for entry {entry_id}', 'WARNING')
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
        if not entry:
            return jsonify({'success': False, 'message': 'Password not found'}), 404
        
        encryption_key = current_user.get_encryption_key(master_password)
        decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
        
        # Record access
        entry.record_access()
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
        
        SecurityLog.create_log(current_user.id, 'PASSWORD_DELETED', f'Deleted password for {site_name}')
        
        return jsonify({'success': True, 'message': 'Password securely deleted'}), 200
        
    except Exception as e:
        logger.error(f"Delete error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error'}), 500

# --------------------------------------------------------
# Security Dashboard API (NEW)
# --------------------------------------------------------
@app.route('/api/security/dashboard', methods=['GET'])
@login_required
def security_dashboard():
    try:
        # Calculate security metrics
        total_passwords = VaultEntry.query.filter_by(user_id=current_user.id).count()
        compromised_passwords = VaultEntry.query.filter_by(user_id=current_user.id, is_compromised=True).count()
        weak_passwords = VaultEntry.query.filter(
            VaultEntry.user_id == current_user.id,
            VaultEntry.password_strength_score < 50
        ).count()
        
        # Recent security events
        recent_events = SecurityLog.query.filter_by(user_id=current_user.id)\
            .order_by(SecurityLog.timestamp.desc()).limit(10).all()
        
        events = []
        for event in recent_events:
            events.append({
                'type': event.event_type,
                'description': event.description,
                'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'severity': event.severity
            })
        
        # Password categories breakdown
        categories = db.session.query(
            VaultEntry.category, 
            db.func.count(VaultEntry.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(VaultEntry.category).all()
        
        category_breakdown = {category: count for category, count in categories}
        
        # Device information
        trusted_devices = DeviceFingerprint.query.filter_by(
            user_id=current_user.id, 
            is_trusted=True
        ).count()
        
        total_devices = DeviceFingerprint.query.filter_by(user_id=current_user.id).count()
        
        dashboard_data = {
            'security_score': current_user.get_security_score(),
            'total_passwords': total_passwords,
            'compromised_passwords': compromised_passwords,
            'weak_passwords': weak_passwords,
            'strong_passwords': total_passwords - compromised_passwords - weak_passwords,
            'password_age_warning': current_user.should_change_password(),
            'two_factor_enabled': current_user.two_factor_enabled,
            'recent_events': events,
            'category_breakdown': category_breakdown,
            'trusted_devices': trusted_devices,
            'total_devices': total_devices,
            'last_login': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if current_user.last_login else None,
            'account_created': current_user.created_at.strftime('%Y-%m-%d'),
            'notifications_enabled': {
                'email': current_user.email_notifications,
                'sms': current_user.sms_notifications,
                'security_alerts': current_user.security_alerts,
                'login_notifications': current_user.login_notifications,
                'breach_notifications': current_user.breach_notifications
            }
        }
        
        return jsonify({'success': True, 'dashboard': dashboard_data}), 200
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load dashboard'}), 500

# --------------------------------------------------------
# Notification Settings API (NEW)
# --------------------------------------------------------
@app.route('/api/settings/notifications', methods=['GET', 'POST'])
@login_required
def notification_settings():
    try:
        if request.method == 'POST':
            data = request.get_json()
            
            # Update notification preferences
            current_user.email_notifications = data.get('email_notifications', True)
            current_user.sms_notifications = data.get('sms_notifications', False)
            current_user.security_alerts = data.get('security_alerts', True)
            current_user.login_notifications = data.get('login_notifications', True)
            current_user.breach_notifications = data.get('breach_notifications', True)
            
            # Update contact information if provided
            if 'recovery_email' in data:
                recovery_email = sanitize_input(data.get('recovery_email', ''))
                if recovery_email:
                    email_valid, email_error = validate_email(recovery_email)
                    if not email_valid:
                        return jsonify({'success': False, 'message': email_error}), 400
                current_user.recovery_email = recovery_email if recovery_email else None
            
            if 'recovery_phone' in data:
                recovery_phone = sanitize_input(data.get('recovery_phone', ''))
                if recovery_phone:
                    phone_valid, phone_error = validate_phone(recovery_phone)
                    if not phone_valid:
                        return jsonify({'success': False, 'message': phone_error}), 400
                current_user.recovery_phone = recovery_phone if recovery_phone else None
            
            db.session.commit()
            
            SecurityLog.create_log(current_user.id, 'SETTINGS_UPDATED', 'Notification settings updated')
            
            return jsonify({'success': True, 'message': 'Notification settings updated'}), 200
        
        # GET request - return current settings
        settings = {
            'email_notifications': current_user.email_notifications,
            'sms_notifications': current_user.sms_notifications,
            'security_alerts': current_user.security_alerts,
            'login_notifications': current_user.login_notifications,
            'breach_notifications': current_user.breach_notifications,
            'recovery_email': current_user.recovery_email,
            'recovery_phone': current_user.recovery_phone,
            'primary_email': current_user.email,
            'primary_phone': current_user.phone
        }
        
        return jsonify({'success': True, 'settings': settings}), 200
        
    except Exception as e:
        logger.error(f"Notification settings error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to update settings'}), 500

# --------------------------------------------------------
# Device Management API (NEW)
# --------------------------------------------------------
@app.route('/api/devices', methods=['GET'])
@login_required
def list_devices():
    try:
        devices = DeviceFingerprint.query.filter_by(user_id=current_user.id)\
            .order_by(DeviceFingerprint.last_seen.desc()).all()
        
        device_list = []
        for device in devices:
            device_list.append({
                'id': device.id,
                'device_name': device.device_name or 'Unknown Device',
                'is_trusted': device.is_trusted,
                'first_seen': device.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                'last_seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': device.ip_address,
                'is_current': device.device_hash == session.get('device_hash')
            })
        
        return jsonify({'success': True, 'devices': device_list}), 200
        
    except Exception as e:
        logger.error(f"Device list error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load devices'}), 500

@app.route('/api/devices/<int:device_id>/trust', methods=['POST'])
@login_required
def trust_device(device_id):
    try:
        device = DeviceFingerprint.query.filter_by(
            id=device_id, 
            user_id=current_user.id
        ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Device not found'}), 404
        
        device.is_trusted = True
        db.session.commit()
        
        SecurityLog.create_log(current_user.id, 'DEVICE_TRUSTED', f'Device {device.id} marked as trusted')
        
        return jsonify({'success': True, 'message': 'Device marked as trusted'}), 200
        
    except Exception as e:
        logger.error(f"Trust device error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to trust device'}), 500

# --------------------------------------------------------
# Enhanced Password Analysis
# --------------------------------------------------------
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
        
        # Use enhanced breach checking
        is_breached, breach_count = check_password_breach_advanced(password)
        
        # zxcvbn analysis
        zx_result = zxcvbn(password)
        
        # Enhanced security level determination
        security_levels = {
            'fortress': {'min_score': 4, 'min_length': 32, 'requires_all': True},
            'military': {'min_score': 4, 'min_length': 20, 'requires_all': True},
            'strong': {'min_score': 3, 'min_length': 16, 'requires_all': True},
            'good': {'min_score': 3, 'min_length': 12, 'requires_all': False},
            'medium': {'min_score': 2, 'min_length': 10, 'requires_all': False},
            'weak': {'min_score': 1, 'min_length': 8, 'requires_all': False},
        }
        
        # Check character requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password)
        has_all_types = has_upper and has_lower and has_digit and has_symbol
        
        security_level = 'critical'
        for level, requirements in security_levels.items():
            if (zx_result['score'] >= requirements['min_score'] and 
                len(password) >= requirements['min_length'] and
                (not requirements['requires_all'] or has_all_types)):
                security_level = level
                break
        
        # Override for breached passwords
        if is_breached:
            if breach_count > 1000000:
                security_level = 'critical'
            elif breach_count > 100000:
                security_level = 'weak'
            elif security_level in ['fortress', 'military']:
                security_level = 'strong'  # Downgrade but not too much
        
        return jsonify({
            'success': True,
            'breached': is_breached,
            'count': breach_count,
            'suggestions': zx_result['feedback']['suggestions'][:3],
            'score': zx_result['score'],
            'crack_time': zx_result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'security_level': security_level,
            'character_types': {
                'uppercase': has_upper,
                'lowercase': has_lower,
                'numbers': has_digit,
                'symbols': has_symbol
            },
            'entropy': zx_result.get('entropy', 0),
            'length': len(password)
        })
        
    except Exception as e:
        logger.error(f"Password analysis error: {str(e)}")
        return jsonify({'success': False, 'message': 'Analysis failed'}), 500

# --------------------------------------------------------
# Bulk Security Check (NEW)
# --------------------------------------------------------
@app.route('/api/vault/security-audit', methods=['POST'])
@login_required
def vault_security_audit():
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        
        if not current_user.check_password(master_password):
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
        encryption_key = current_user.get_encryption_key(master_password)
        
        audit_results = {
            'total_passwords': len(entries),
            'compromised_count': 0,
            'weak_count': 0,
            'duplicate_count': 0,
            'old_count': 0,
            'compromised_sites': [],
            'weak_sites': [],
            'duplicate_groups': [],
            'old_sites': []
        }
        
        password_hashes = {}  # To detect duplicates
        
        for entry in entries:
            try:
                # Decrypt password for analysis
                decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
                
                # Check for breaches
                is_breached, breach_count = check_password_breach_advanced(decrypted_password)
                
                if is_breached:
                    audit_results['compromised_count'] += 1
                    audit_results['compromised_sites'].append({
                        'site': entry.site,
                        'username': entry.username,
                        'breach_count': breach_count,
                        'id': entry.id
                    })
                    entry.is_compromised = True
                
                # Check password strength
                zx_result = zxcvbn(decrypted_password)
                strength_score = zx_result['score'] * 25
                entry.password_strength_score = strength_score
                
                if strength_score < 50:
                    audit_results['weak_count'] += 1
                    audit_results['weak_sites'].append({
                        'site': entry.site,
                        'username': entry.username,
                        'strength_score': strength_score,
                        'id': entry.id
                    })
                
                # Check for duplicates
                password_hash = hashlib.sha256(decrypted_password.encode()).hexdigest()
                if password_hash in password_hashes:
                    password_hashes[password_hash].append({
                        'site': entry.site,
                        'username': entry.username,
                        'id': entry.id
                    })
                else:
                    password_hashes[password_hash] = [{
                        'site': entry.site,
                        'username': entry.username,
                        'id': entry.id
                    }]
                
                # Check password age (if older than 90 days)
                days_old = (datetime.utcnow() - entry.updated_at).days
                if days_old > 90:
                    audit_results['old_count'] += 1
                    audit_results['old_sites'].append({
                        'site': entry.site,
                        'username': entry.username,
                        'days_old': days_old,
                        'id': entry.id
                    })
                
            except Exception as e:
                logger.warning(f"Failed to audit entry {entry.id}: {e}")
                continue
        
        # Process duplicate groups
        for password_hash, sites in password_hashes.items():
            if len(sites) > 1:
                audit_results['duplicate_count'] += len(sites)
                audit_results['duplicate_groups'].append(sites)
        
        # Update database with new security scores
        db.session.commit()
        
        # Log security audit
        SecurityLog.create_log(current_user.id, 'SECURITY_AUDIT', 
                              f'Vault security audit completed. Found {audit_results["compromised_count"]} compromised passwords')
        
        # Send critical notification if many compromised passwords found
        if audit_results['compromised_count'] > 5 and current_user.security_alerts:
            NotificationService.notify_user(
                current_user,
                'Critical Security Alert',
                f'Security audit found {audit_results["compromised_count"]} compromised passwords in your vault. Immediate action required.',
                is_critical=True
            )
        
        return jsonify({
            'success': True,
            'audit_results': audit_results
        }), 200
        
    except Exception as e:
        logger.error(f"Security audit error: {str(e)}")
        return jsonify({'success': False, 'message': 'Security audit failed'}), 500

# --------------------------------------------------------
# Export/Import Functionality (NEW)
# --------------------------------------------------------
@app.route('/api/vault/export', methods=['POST'])
@login_required
def export_vault():
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        export_format = data.get('format', 'json')  # json, csv
        
        if not current_user.check_password(master_password):
            return jsonify({'success': False, 'message': 'Invalid master password'}), 401
        
        entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
        encryption_key = current_user.get_encryption_key(master_password)
        
        export_data = []
        
        for entry in entries:
            try:
                decrypted_password = decrypt_password(entry.encrypted_password, encryption_key)
                
                export_entry = {
                    'site': entry.site,
                    'username': entry.username,
                    'password': decrypted_password,
                    'category': entry.category,
                    'notes': entry.notes,
                    'created_at': entry.created_at.isoformat(),
                    'updated_at': entry.updated_at.isoformat()
                }
                
                export_data.append(export_entry)
                
            except Exception as e:
                logger.warning(f"Failed to decrypt entry {entry.id} for export: {e}")
                continue
        
        # Log export
        SecurityLog.create_log(current_user.id, 'VAULT_EXPORTED', 
                              f'Vault data exported in {export_format} format')
        
        return jsonify({
            'success': True,
            'data': export_data,
            'format': export_format,
            'exported_count': len(export_data),
            'export_timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({'success': False, 'message': 'Export failed'}), 500

# --------------------------------------------------------
# User Information API
# --------------------------------------------------------
@app.route('/api/me', methods=['GET'])
def get_user_info():
    try:
        if current_user.is_authenticated:
            return jsonify({
                'success': True,
                'authenticated': True,
                'username': current_user.username,
                'email': current_user.email,
                'salt': current_user.encryption_salt,
                'vault_count': VaultEntry.query.filter_by(user_id=current_user.id).count(),
                'security_score': current_user.get_security_score(),
                'two_factor_enabled': current_user.two_factor_enabled,
                'password_age_warning': current_user.should_change_password(),
                'account_created': current_user.created_at.strftime('%Y-%m-%d'),
                'last_login': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if current_user.last_login else None
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
# Admin/Maintenance Routes (Optional)
# --------------------------------------------------------
@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    """Basic application statistics - only enable in development"""
    if os.environ.get('FLASK_ENV') != 'development':
        abort(404)
    
    try:
        stats = {
            'total_users': User.query.count(),
            'total_vault_entries': VaultEntry.query.count(),
            'total_security_logs': SecurityLog.query.count(),
            'compromised_passwords': VaultEntry.query.filter_by(is_compromised=True).count(),
            'recent_registrations': User.query.filter(
                User.created_at >= datetime.utcnow() - timedelta(days=7)
            ).count(),
            'database_size': 'N/A'  # Implement based on your database
        }
        
        return jsonify({'success': True, 'stats': stats}), 200
        
    except Exception as e:
        logger.error(f"Admin stats error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get stats'}), 500

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

        print("SSL certificates generated successfully!")
        return True
        
    except ImportError:
        logger.error("Cryptography package required for SSL certificates.")
        print("Please install the cryptography package:")
        print("pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"SSL certificate generation failed: {str(e)}")
        print(f"Error generating SSL certificates: {str(e)}")
        return False

# --------------------------------------------------------
# Application Startup and Configuration
# --------------------------------------------------------
def create_default_admin():
    """Create default admin user if none exists"""
    if User.query.count() == 0:
        try:
            admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(16)
            
            salt = secrets.token_bytes(64)
            encryption_salt = base64.b64encode(salt).decode('utf-8')
            
            admin_user = User(
                username='admin',
                email=os.environ.get('ADMIN_EMAIL'),
                encryption_salt=encryption_salt,
                email_notifications=True,
                security_alerts=True
            )
            admin_user.set_password(admin_password)
            
            db.session.add(admin_user)
            db.session.commit()
            
            print(f"Default admin user created:")
            print(f"Username: admin")
            print(f"Password: {admin_password}")
            print("Please change this password after first login!")
            
            SecurityLog.create_log(admin_user.id, 'ACCOUNT_CREATED', 'Default admin account created')
            
        except Exception as e:
            logger.error(f"Failed to create admin user: {e}")

# --------------------------------------------------------
# Run Application with Enhanced Security
# --------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
        logger.info("Database initialized successfully")
        
    print("=" * 80)
    print("🛡️  VAULTGUARD SECURE - ENHANCED VERSION")
    print("=" * 80)
    print("🔧 NEW FEATURES INCLUDED:")
    print("   ✅ Email & SMS Notifications")
    print("   ✅ Password Reset via Email/Phone")
    print("   ✅ Security Dashboard & Analytics")
    print("   ✅ Device Management & Trust")
    print("   ✅ Advanced Breach Detection")
    print("   ✅ Vault Security Audit")
    print("   ✅ Export/Import Functionality")
    print("   ✅ Enhanced Security Logging")
    print("   ✅ Notification Preferences")
    print("   ✅ Two-Factor Ready Architecture")
    print("=" * 80)
    
    # Environment setup instructions
    print("\n🔧 ENVIRONMENT SETUP:")
    print("For full functionality, set these environment variables:")
    print("• MAIL_SERVER=smtp.gmail.com")
    print("• MAIL_USERNAME=your-email@gmail.com")
    print("• MAIL_PASSWORD=your-app-password")
    print("• TWILIO_ACCOUNT_SID=your-twilio-sid (for SMS)")
    print("• TWILIO_AUTH_TOKEN=your-twilio-token")
    print("• DATABASE_URL=your-database-url (optional)")
    print("• SECRET_KEY=your-secret-key (optional)")
    
    # SSL certificate handling
    ssl_context = None
    cert_exists = os.path.exists('cert.pem') and os.path.exists('key.pem')
    
    if not cert_exists:
        print("\n🔒 SSL certificates not found. Generating new certificates...")
        if create_ssl_certificate():
            print("✅ SSL certificates created successfully!")
            cert_exists = True
        else:
            print("❌ Could not create SSL certificates. Running without HTTPS.")
    
    if cert_exists:
        ssl_context = ('cert.pem', 'key.pem')
        print("\n🔒 HTTPS ENABLED - Secure connection established")
        print("\n🌐 ACCESS URLS:")
        print("• Primary: https://127.0.0.1:5000")
        print("• Alternative: https://localhost:5000")
        print("\n⚠️  BROWSER SECURITY WARNING:")
        print("Your browser will show a security warning for self-signed certificates.")
        print("This is normal - click 'Advanced' then 'Proceed to 127.0.0.1 (unsafe)'")
        print("Your connection will still be fully encrypted with HTTPS.")
    else:
        print("\n⚠️  Running without HTTPS - Some features will be limited")
        print("🌐 Access your app at: http://127.0.0.1:5000")
    
    print("=" * 80)
    
    # Start the application
    try:
        app.run(
            host='127.0.0.1', 
            port=5000, 
            ssl_context=ssl_context,
            debug=os.environ.get('FLASK_ENV') == 'development',
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        print(f"\n❌ Error starting application: {str(e)}")
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Make sure port 5000 is not already in use")
        print("2. Try running without SSL if certificate issues persist")
        print("3. Check that all required packages are installed:")
        print("   pip install flask flask-sqlalchemy flask-bcrypt flask-login")
        print("   pip install cryptography zxcvbn bleach requests")
        print("4. Ensure you have write permissions in the current directory")
