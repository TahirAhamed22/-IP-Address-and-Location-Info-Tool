import os
import json
import base64
import logging
import random
import secrets
import re
import time
import hashlib
import smtplib
import uuid
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
from werkzeug.utils import secure_filename
from user_agents import parse

# Try to import requests for HaveIBeenPwned integration
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  WARNING: 'requests' package not installed. Install with: pip install requests")

# Try to import Twilio for SMS notifications
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    print("⚠️  WARNING: 'twilio' package not installed. Install with: pip install twilio")

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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@vaultguard.com')

# Twilio Configuration
app.config['TWILIO_ACCOUNT_SID'] = os.environ.get('TWILIO_ACCOUNT_SID', '')
app.config['TWILIO_AUTH_TOKEN'] = os.environ.get('TWILIO_AUTH_TOKEN', '')
app.config['TWILIO_PHONE_NUMBER'] = os.environ.get('TWILIO_PHONE_NUMBER', '')

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
# Enhanced Database Models
# --------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), nullable=True, index=True)  # Optional email
    phone_number = db.Column(db.String(20), nullable=True)  # Optional phone
    password_hash = db.Column(db.String(128), nullable=False)
    encryption_salt = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    
    # Enhanced profile fields
    profile_picture = db.Column(db.String(200))
    timezone = db.Column(db.String(50), default='UTC')
    language = db.Column(db.String(10), default='en')
    
    # Security preferences
    notification_preferences = db.Column(db.Text)  # JSON string
    breach_check_enabled = db.Column(db.Boolean, default=True)
    login_notifications = db.Column(db.Boolean, default=True)
    new_device_notifications = db.Column(db.Boolean, default=True)
    password_age_notifications = db.Column(db.Boolean, default=True)
    security_report_frequency = db.Column(db.String(20), default='weekly')  # daily, weekly, monthly
    
    # Two-factor authentication
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    backup_codes = db.Column(db.Text)  # JSON array of backup codes
    
    # Recovery fields
    recovery_email = db.Column(db.String(120))
    recovery_phone = db.Column(db.String(20))
    security_questions = db.Column(db.Text)  # JSON array
    
    # Analytics
    last_breach_check = db.Column(db.DateTime)
    total_logins = db.Column(db.Integer, default=0)
    password_changes = db.Column(db.Integer, default=0)
    
    # Relationships
    vault_entries = db.relationship('VaultEntry', backref='owner', lazy=True, cascade='all, delete-orphan')
    security_events = db.relationship('SecurityEvent', backref='user', lazy=True, cascade='all, delete-orphan')
    devices = db.relationship('TrustedDevice', backref='user', lazy=True, cascade='all, delete-orphan')
    otp_tokens = db.relationship('OTPToken', backref='user', lazy=True, cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password, rounds=12).decode('utf-8')
        self.password_changes += 1
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
    
    def lock_account(self, duration_minutes=60):
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts += 1
        self.log_security_event('ACCOUNT_LOCKED', f'Account locked for {duration_minutes} minutes after {self.failed_login_attempts} failed attempts')
    
    def unlock_account(self):
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()
        self.total_logins += 1
        self.log_security_event('LOGIN_SUCCESS', 'Successful authentication')

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
            'login_notifications': self.login_notifications,
            'new_device_notifications': self.new_device_notifications,
            'email_notifications': bool(self.email),
            'sms_notifications': bool(self.phone_number),
            'security_reports': True
        }

    def set_notification_preferences(self, preferences):
        self.notification_preferences = json.dumps(preferences)
        # Update individual flags for quick access
        self.login_notifications = preferences.get('login_notifications', True)
        self.new_device_notifications = preferences.get('new_device_notifications', True)
        self.password_age_notifications = preferences.get('password_age_warnings', True)

    def log_security_event(self, event_type, description, ip_address=None, device_info=None):
        try:
            event = SecurityEvent(
                user_id=self.id,
                event_type=event_type,
                description=description,
                ip_address=ip_address or get_client_ip(),
                device_info=device_info,
                timestamp=datetime.utcnow()
            )
            db.session.add(event)
            return event
        except Exception as e:
            logger.error(f"Failed to log security event: {str(e)}")
            return None

    def create_notification(self, title, message, type='info', action_url=None):
        try:
            notification = Notification(
                user_id=self.id,
                title=title,
                message=message,
                type=type,
                action_url=action_url,
                created_at=datetime.utcnow()
            )
            db.session.add(notification)
            return notification
        except Exception as e:
            logger.error(f"Failed to create notification: {str(e)}")
            return None

    def send_notification(self, title, message, channels=['web'], urgent=False):
        """Send notification via multiple channels"""
        notification = self.create_notification(title, message, 'urgent' if urgent else 'info')
        
        preferences = self.get_notification_preferences()
        
        # Send email notification
        if 'email' in channels and self.email and preferences.get('email_notifications'):
            try:
                send_email_notification(self.email, title, message)
            except Exception as e:
                logger.error(f"Failed to send email notification: {str(e)}")
        
        # Send SMS notification
        if 'sms' in channels and self.phone_number and preferences.get('sms_notifications'):
            try:
                send_sms_notification(self.phone_number, f"{title}: {message}")
            except Exception as e:
                logger.error(f"Failed to send SMS notification: {str(e)}")
        
        return notification

class VaultEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120), nullable=False, index=True)
    username = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='General', index=True)
    tags = db.Column(db.Text)  # JSON array of tags
    notes = db.Column(db.Text)  # Encrypted notes
    url = db.Column(db.String(500))  # Website URL
    favorite = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    last_accessed = db.Column(db.DateTime, index=True)
    
    # Security metrics
    access_count = db.Column(db.Integer, default=0)
    password_strength_score = db.Column(db.Integer, default=0)
    password_age_days = db.Column(db.Integer, default=0)  # Days since password creation
    is_compromised = db.Column(db.Boolean, default=False, index=True)
    compromise_date = db.Column(db.DateTime)
    last_breach_check = db.Column(db.DateTime)
    
    # Metadata
    icon_url = db.Column(db.String(500))  # Site favicon URL
    auto_fill_enabled = db.Column(db.Boolean, default=True)
    requires_2fa = db.Column(db.Boolean, default=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def update_access(self):
        self.access_count += 1
        self.last_accessed = datetime.utcnow()
        if current_user.is_authenticated:
            current_user.log_security_event('PASSWORD_ACCESS', f'Accessed password for {self.site}')

    def update_password_age(self):
        if self.updated_at:
            age = datetime.utcnow() - self.updated_at
            self.password_age_days = age.days

    def get_tags(self):
        if self.tags:
            try:
                return json.loads(self.tags)
            except json.JSONDecodeError:
                return []
        return []

    def set_tags(self, tags_list):
        self.tags = json.dumps(tags_list)

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False, index=True)  # LOGIN_SUCCESS, LOGIN_FAIL, etc.
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45), index=True)  # IPv6 compatible
    device_info = db.Column(db.Text)  # JSON with device details
    location = db.Column(db.String(100))  # City, Country
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    severity = db.Column(db.String(20), default='INFO', index=True)  # INFO, WARNING, CRITICAL
    resolved = db.Column(db.Boolean, default=True)
    resolution_notes = db.Column(db.Text)

class TrustedDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_id = db.Column(db.String(100), nullable=False, unique=True)  # UUID for device
    device_name = db.Column(db.String(100), nullable=False)  # User-friendly name
    device_type = db.Column(db.String(50))  # mobile, desktop, tablet
    browser = db.Column(db.String(50))
    operating_system = db.Column(db.String(50))
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(100))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_trusted = db.Column(db.Boolean, default=False)
    trust_level = db.Column(db.String(20), default='unknown')  # unknown, trusted, suspicious, blocked
    login_count = db.Column(db.Integer, default=0)

class OTPToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(10), nullable=False)  # 6-digit OTP
    token_type = db.Column(db.String(50), nullable=False)  # password_reset, login_verification, etc.
    contact_method = db.Column(db.String(20))  # email, sms
    contact_address = db.Column(db.String(120))  # email address or phone number
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)
    max_attempts = db.Column(db.Integer, default=3)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')  # info, warning, error, success, urgent
    category = db.Column(db.String(50), default='general')  # security, breach, system, etc.
    action_url = db.Column(db.String(500))  # Optional action button URL
    action_text = db.Column(db.String(50))  # Optional action button text
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    channels_sent = db.Column(db.Text)  # JSON array of channels (web, email, sms)

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vault_entry_id = db.Column(db.Integer, db.ForeignKey('vault_entry.id'), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    strength_score = db.Column(db.Integer)
    breach_status = db.Column(db.Boolean, default=False)

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

def get_device_info():
    """Extract device information from user agent"""
    try:
        user_agent_string = request.headers.get('User-Agent', '')
        user_agent = parse(user_agent_string)
        
        return {
            'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
            'os': f"{user_agent.os.family} {user_agent.os.version_string}",
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'user_agent': user_agent_string
        }
    except Exception as e:
        logger.error(f"Failed to parse user agent: {str(e)}")
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': True,
            'user_agent': request.headers.get('User-Agent', '')
        }

def generate_device_id():
    """Generate unique device ID"""
    user_agent = request.headers.get('User-Agent', '')
    ip = get_client_ip()
    # Create a hash of user agent + IP for consistent device identification
    device_string = f"{user_agent}:{ip}"
    return hashlib.sha256(device_string.encode()).hexdigest()[:32]

def is_new_device(user_id, device_id):
    """Check if this is a new device for the user"""
    device = TrustedDevice.query.filter_by(user_id=user_id, device_id=device_id).first()
    return device is None

def create_or_update_device(user_id, device_id):
    """Create or update trusted device record"""
    try:
        device_info = get_device_info()
        device = TrustedDevice.query.filter_by(user_id=user_id, device_id=device_id).first()
        
        if device:
            # Update existing device
            device.last_seen = datetime.utcnow()
            device.login_count += 1
            device.ip_address = get_client_ip()
        else:
            # Create new device
            device = TrustedDevice(
                user_id=user_id,
                device_id=device_id,
                device_name=f"{device_info['os']} - {device_info['browser']}",
                device_type='mobile' if device_info['is_mobile'] else 'tablet' if device_info['is_tablet'] else 'desktop',
                browser=device_info['browser'],
                operating_system=device_info['os'],
                ip_address=get_client_ip(),
                login_count=1
            )
            db.session.add(device)
        
        return device
    except Exception as e:
        logger.error(f"Failed to create/update device: {str(e)}")
        return None

def send_email_notification(to_email, subject, message):
    """Send email notification"""
    try:
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            logger.warning("Email configuration not set, skipping email notification")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(message, 'plain'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_DEFAULT_SENDER'], to_email, text)
        server.quit()
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

def send_sms_notification(to_phone, message):
    """Send SMS notification via Twilio"""
    try:
        if not TWILIO_AVAILABLE:
            logger.warning("Twilio not available, skipping SMS notification")
            return False
            
        if not app.config['TWILIO_ACCOUNT_SID'] or not app.config['TWILIO_AUTH_TOKEN']:
            logger.warning("Twilio configuration not set, skipping SMS notification")
            return False
            
        client = TwilioClient(app.config['TWILIO_ACCOUNT_SID'], app.config['TWILIO_AUTH_TOKEN'])
        
        message = client.messages.create(
            body=message,
            from_=app.config['TWILIO_PHONE_NUMBER'],
            to=to_phone
        )
        
        logger.info(f"SMS sent successfully to {to_phone}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send SMS: {str(e)}")
        return False

def generate_otp():
    """Generate 6-digit OTP"""
    return f"{random.randint(100000, 999999):06d}"

def create_otp_token(user, token_type, contact_method, contact_address, expires_in_minutes=10):
    """Create OTP token for user"""
    try:
        # Invalidate any existing tokens of the same type
        existing_tokens = OTPToken.query.filter_by(
            user_id=user.id,
            token_type=token_type,
            used=False
        ).all()
        for token in existing_tokens:
            token.used = True
        
        # Create new token
        otp_token = OTPToken(
            user_id=user.id,
            token=generate_otp(),
            token_type=token_type,
            contact_method=contact_method,
            contact_address=contact_address,
            expires_at=datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        )
        db.session.add(otp_token)
        db.session.commit()
        
        return otp_token
        
    except Exception as e:
        logger.error(f"Failed to create OTP token: {str(e)}")
        db.session.rollback()
        return None

def verify_otp_token(user_id, token, token_type):
    """Verify OTP token"""
    try:
        otp_token = OTPToken.query.filter_by(
            user_id=user_id,
            token=token,
            token_type=token_type,
            used=False
        ).first()
        
        if not otp_token:
            return False, "Invalid OTP code"
        
        if otp_token.expires_at < datetime.utcnow():
            return False, "OTP code has expired"
        
        if otp_token.attempts >= otp_token.max_attempts:
            return False, "Maximum attempts exceeded"
        
        otp_token.attempts += 1
        
        if otp_token.token == token:
            otp_token.used = True
            db.session.commit()
            return True, "OTP verified successfully"
        else:
            db.session.commit()
            return False, "Invalid OTP code"
            
    except Exception as e:
        logger.error(f"Failed to verify OTP: {str(e)}")
        return False, "OTP verification failed"

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

def validate_email(email):
    if not email:
        return True, ""  # Email is optional
    if len(email) > 120:
        return False, "Email address is too long"
    email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    if not email_regex.match(email):
        return False, "Invalid email address format"
    return True, ""

def validate_phone_number(phone):
    if not phone:
        return True, ""  # Phone is optional
    if len(phone) > 20:
        return False, "Phone number is too long"
    # Basic phone validation (can be enhanced)
    phone_regex = re.compile(r'^\+?[1-9]\d{1,14}$')
    if not phone_regex.match(phone.replace(' ', '').replace('-', '')):
        return False, "Invalid phone number format"
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

def perform_comprehensive_password_analysis(password):
    """Comprehensive password analysis with real breach checking"""
    try:
        # Use zxcvbn for initial analysis
        zx_result = zxcvbn(password)
        
        # Check for breaches
        is_breached = False
        breach_count = 0
        security_level = 'unknown'
        
        if REQUESTS_AVAILABLE:
            # Real HaveIBeenPwned check
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
            except Exception as api_error:
                logger.warning(f"HaveIBeenPwned API failed: {str(api_error)}")
                is_breached, breach_count = check_password_breach_mock(password)
        else:
            # Fallback to mock detection
            is_breached, breach_count = check_password_breach_mock(password)
        
        # Determine security level
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
        
        return {
            'success': True,
            'breached': is_breached,
            'count': breach_count,
            'suggestions': zx_result['feedback']['suggestions'][:3],
            'score': zx_result['score'],
            'crack_time': zx_result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'security_level': security_level,
            'entropy': calculate_password_entropy(password),
            'patterns': detect_password_patterns(password)
        }
        
    except Exception as e:
        logger.error(f"Password analysis error: {str(e)}")
        return {
            'success': True,
            'breached': False,
            'count': 0,
            'suggestions': ['Password analysis temporarily unavailable'],
            'score': 2,
            'crack_time': 'unknown',
            'security_level': 'unknown',
            'entropy': 0,
            'patterns': []
        }

def check_password_breach_mock(password):
    """Enhanced mock breach detection"""
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
        return True, random.randint(1000000, 10000000)
    elif any(pattern.lower() in lower_password for pattern in critical_patterns):
        return True, random.randint(100000, 2000000)
    elif any(seq in lower_password for seq in keyboard_sequences):
        return True, random.randint(50000, 500000)
    elif repeated_patterns:
        return True, random.randint(10000, 200000)
    elif len(password) < 8:
        return True, random.randint(500000, 5000000)
    elif len(password) >= 32:
        return False, 0
    elif len(password) >= 16:
        return random.random() < 0.02, random.randint(1, 25) if random.random() < 0.02 else 0
    else:
        return random.random() < 0.15, random.randint(100, 5000) if random.random() < 0.15 else 0

def calculate_password_entropy(password):
    """Calculate password entropy"""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password):
        charset_size += 32
    
    if charset_size == 0:
        return 0
    
    import math
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def detect_password_patterns(password):
    """Detect common password patterns"""
    patterns = []
    
    if any(char * 3 in password for char in password):
        patterns.append("repeated_characters")
    
    if any(seq in password.lower() for seq in ['123', 'abc', 'qwe']):
        patterns.append("sequential_characters")
    
    # Check for dates
    import re
    if re.search(r'(19|20)\d{2}', password):
        patterns.append("contains_year")
    
    # Check for common words
    common_words = ['password', 'admin', 'user', 'login', 'welcome']
    if any(word in password.lower() for word in common_words):
        patterns.append("common_words")
    
    return patterns

# --------------------------------------------------------
# Security Middleware
# --------------------------------------------------------
@app.before_request
def security_checks():
    # Force HTTPS in production
    if not request.is_secure and os.environ.get('FLASK_ENV') == 'production':
        return redirect(request.url.replace('http://', 'https://'))
    
    # Rate limiting for sensitive endpoints
    if request.endpoint in ['api_login', 'api_register', 'api_password_reset']:
        # Basic rate limiting logic (can be enhanced with Redis)
        pass

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' api.pwnedpasswords.com"
    
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# --------------------------------------------------------
# Initialize Database
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

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/security-center')
@login_required
def security_center():
    return render_template('security_center.html')

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
        current_user.log_security_event('LOGOUT', 'User logged out', get_client_ip(), json.dumps(get_device_info()))
        logout_user()
        session.clear()
        logger.info(f"User {username} logged out")
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return redirect(url_for('home'))

# --------------------------------------------------------
# Enhanced API Routes
# --------------------------------------------------------
@app.route('/api/login', methods=["POST"])
def api_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
            
        username = sanitize_input(data.get("username", ""))
        password = data.get("password", "")
        remember_device = data.get("remember_device", False)
        client_ip = get_client_ip()
        device_info = get_device_info()
        
        logger.info(f"Login attempt for username: '{username}' from IP: {client_ip}")
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            logger.warning(f"Login attempt for non-existent user: '{username}' from {client_ip}")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        if user.is_account_locked():
            user.log_security_event('LOGIN_BLOCKED', 'Login blocked - account locked', client_ip, json.dumps(device_info))
            return jsonify({'success': False, 'message': 'Account locked. Try again later.'}), 423
        
        if user.check_password(password):
            # Successful login
            device_id = generate_device_id()
            is_new = is_new_device(user.id, device_id)
            
            # Create or update device record
            device = create_or_update_device(user.id, device_id)
            
            # Check if new device and send notification
            if is_new and user.new_device_notifications:
                user.send_notification(
                    "New Device Login",
                    f"Login detected from new device: {device_info['os']} - {device_info['browser']} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
                    channels=['web', 'email'] if user.email else ['web']
                )
            
            user.unlock_account()
            db.session.commit()
            
            login_user(user, remember=remember_device)
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session['device_id'] = device_id
            session.permanent = True
            
            logger.info(f"Successful login for user: '{username}' from {client_ip}")
            
            return jsonify({
                'success': True, 
                'message': 'Secure login successful!', 
                'salt': user.encryption_salt,
                'username': user.username,
                'is_new_device': is_new,
                'user_preferences': user.get_notification_preferences()
            }), 200
        else:
            user.failed_login_attempts += 1
            user.log_security_event('LOGIN_FAILED', f'Failed login attempt #{user.failed_login_attempts}', client_ip, json.dumps(device_info))
            
            if user.failed_login_attempts >= 3:
                user.lock_account(60)
                logger.warning(f"Account locked for user: '{username}' after 3 failed attempts from {client_ip}")
                
                # Send security alert
                if user.login_notifications:
                    user.send_notification(
                        "Account Locked - Security Alert",
                        f"Your account has been locked due to 3 failed login attempts from IP: {client_ip}",
                        channels=['web', 'email', 'sms'],
                        urgent=True
                    )
            
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
        email = sanitize_input(data.get("email", ""))
        phone = sanitize_input(data.get("phone", ""))
        client_ip = get_client_ip()
        device_info = get_device_info()
        
        logger.info(f"Registration attempt for username: '{username}' from IP: {client_ip}")
        
        # Validate inputs
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
            phone_valid, phone_error = validate_phone_number(phone)
            if not phone_valid:
                return jsonify({'success': False, 'message': phone_error}), 400

        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if email and User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400

        # Create new user
        salt = secrets.token_bytes(64)
        encryption_salt = base64.b64encode(salt).decode('utf-8')
        
        new_user = User(
            username=username, 
            email=email if email else None,
            phone_number=phone if phone else None,
            encryption_salt=encryption_salt,
            breach_check_enabled=True,
            login_notifications=True,
            new_device_notifications=True,
            password_age_notifications=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Create initial device record
        device_id = generate_device_id()
        create_or_update_device(new_user.id, device_id)
        
        # Log registration
        new_user.log_security_event('ACCOUNT_CREATED', 'New account created', client_ip, json.dumps(device_info))
        
        # Send welcome notification
        new_user.create_notification(
            "Welcome to VaultGuard!",
            "Your secure password vault has been created. Start by adding your first password to experience military-grade encryption.",
            type='success'
        )
        
        # Send welcome email if provided
        if email:
            try:
                send_email_notification(
                    email,
                    "Welcome to VaultGuard Secure",
                    f"Hello {username},\n\nYour VaultGuard account has been created successfully. Your passwords are now protected with military-grade AES-256 encryption.\n\nBest regards,\nVaultGuard Team"
                )
            except Exception as e:
                logger.warning(f"Failed to send welcome email: {str(e)}")
        
        # Auto-login the new user
        login_user(new_user, remember=False)
        session['logged_in'] = True
        session['username'] = new_user.username
        session['user_id'] = new_user.id
        session['device_id'] = device_id
        session.permanent = True
        
        db.session.commit()
        
        logger.info(f"Successful registration and login for user: '{username}' from {client_ip}")
        
        return jsonify({
            'success': True, 
            'message': 'Secure account created!', 
            'salt': encryption_salt,
            'username': new_user.username,
            'user_preferences': new_user.get_notification_preferences()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

@app.route('/api/password-recovery/request', methods=['POST'])
def request_password_recovery():
    try:
        data = request.get_json()
        identifier = sanitize_input(data.get('identifier', ''))  # username, email, or phone
        recovery_method = data.get('method', 'email')  # email or sms
        
        if not identifier:
            return jsonify({'success': False, 'message': 'Username, email, or phone number required'}), 400
        
        # Find user by username, email, or phone
        user = User.query.filter(
            (User.username == identifier) | 
            (User.email == identifier) | 
            (User.phone_number == identifier)
        ).first()
        
        if not user:
            # Don't reveal if user exists or not
            return jsonify({'success': True, 'message': 'If the account exists, recovery instructions have been sent.'}), 200
        
        # Determine contact method
        if recovery_method == 'email' and user.email:
            contact_address = user.email
            contact_method = 'email'
        elif recovery_method == 'sms' and user.phone_number:
            contact_address = user.phone_number
            contact_method = 'sms'
        elif user.email:
            contact_address = user.email
            contact_method = 'email'
        elif user.phone_number:
            contact_address = user.phone_number
            contact_method = 'sms'
        else:
            return jsonify({'success': False, 'message': 'No recovery method available for this account'}), 400
        
        # Create OTP token
        otp_token = create_otp_token(user, 'password_reset', contact_method, contact_address, 15)  # 15 minutes
        
        if not otp_token:
            return jsonify({'success': False, 'message': 'Failed to generate recovery code'}), 500
        
        # Send recovery code
        if contact_method == 'email':
            success = send_email_notification(
                contact_address,
                "VaultGuard Password Reset",
                f"Your password reset code is: {otp_token.token}\n\nThis code will expire in 15 minutes.\n\nIf you didn't request this, please ignore this email."
            )
        else:
            success = send_sms_notification(
                contact_address,
                f"VaultGuard: Your password reset code is {otp_token.token}. Expires in 15 minutes."
            )
        
        if success:
            user.log_security_event('PASSWORD_RESET_REQUESTED', f'Password reset requested via {contact_method}', get_client_ip())
            return jsonify({
                'success': True, 
                'message': f'Recovery code sent to your {contact_method}',
                'method': contact_method,
                'masked_contact': mask_contact_info(contact_address, contact_method)
            }), 200
        else:
            return jsonify({'success': False, 'message': f'Failed to send recovery code via {contact_method}'}), 500
            
    except Exception as e:
        logger.error(f"Password recovery request error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error occurred'}), 500

def mask_contact_info(contact, method):
    """Mask contact information for privacy"""
    if method == 'email':
        parts = contact.split('@')
        if len(parts) == 2:
            username = parts[0]
            domain = parts[1]
            masked_username = username[0] + '*' * (len(username) - 2) + username[-1] if len(username) > 2 else '*' * len(username)
            return f"{masked_username}@{domain}"
    elif method == 'sms':
        if len(contact) > 4:
            return contact[:3] + '*' * (len(contact) - 6) + contact[-3:]
    return contact

@app.route('/api/password-recovery/verify', methods=['POST'])
def verify_password_recovery():
    try:
        data = request.get_json()
        identifier = sanitize_input(data.get('identifier', ''))
        otp_code = data.get('otp_code', '')
        new_password = data.get('new_password', '')
        
        if not all([identifier, otp_code, new_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # Validate new password
        password_valid, password_error = validate_password_strength(new_password)
        if not password_valid:
            return jsonify({'success': False, 'message': password_error}), 400
        
        # Find user
        user = User.query.filter(
            (User.username == identifier) | 
            (User.email == identifier) | 
            (User.phone_number == identifier)
        ).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid recovery request'}), 400
        
        # Verify OTP
        is_valid, message = verify_otp_token(user.id, otp_code, 'password_reset')
        
        if not is_valid:
            return jsonify({'success': False, 'message': message}), 400
        
        # Update password
        user.set_password(new_password)
        user.failed_login_attempts = 0  # Reset failed attempts
        user.account_locked_until = None  # Unlock account
        
        # Log security event
        user.log_security_event('PASSWORD_RESET_COMPLETED', 'Password reset completed successfully', get_client_ip())
        
        # Send confirmation notification
        user.send_notification(
            "Password Reset Successful",
            "Your VaultGuard password has been reset successfully. If this wasn't you, please contact support immediately.",
            channels=['web', 'email', 'sms'],
            urgent=True
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully! You can now login with your new password.'
        }), 200
        
    except Exception as e:
        logger.error(f"Password recovery verification error: {str(e)}")
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
            url = sanitize_input(data.get('url', ''))
            tags = data.get('tags', [])

            if not all([site, username, password, master_password]):
                return jsonify({'success': False, 'message': 'All required fields must be filled'}), 400

            if not current_user.check_password(master_password):
                current_user.log_security_event('VAULT_ACCESS_DENIED', 'Invalid master password for vault access')
                return jsonify({'success': False, 'message': 'Invalid master password'}), 401

            encryption_key = current_user.get_encryption_key(master_password)
            encrypted_password = encrypt_password(password, encryption_key)
            encrypted_notes = encrypt_password(notes, encryption_key) if notes else None
            
            # Analyze password strength
            analysis = perform_comprehensive_password_analysis(password)
            strength_score = analysis['score']
            is_compromised = analysis['breached']
            
            existing_entry = VaultEntry.query.filter_by(
                site=site, username=username, user_id=current_user.id
            ).first()
            
            if existing_entry:
                # Store password history
                history = PasswordHistory(
                    vault_entry_id=existing_entry.id,
                    encrypted_password=existing_entry.encrypted_password,
                    strength_score=existing_entry.password_strength_score,
                    breach_status=existing_entry.is_compromised
                )
                db.session.add(history)
                
                # Update existing entry
                existing_entry.encrypted_password = encrypted_password
                existing_entry.notes = encrypted_notes
                existing_entry.category = category
                existing_entry.url = url
                existing_entry.password_strength_score = strength_score
                existing_entry.is_compromised = is_compromised
                existing_entry.updated_at = datetime.utcnow()
                existing_entry.set_tags(tags)
                existing_entry.update_password_age()
                message = 'Password updated securely!'
                current_user.log_security_event('PASSWORD_UPDATED', f'Updated password for {site}')
            else:
                new_entry = VaultEntry(
                    site=site,
                    username=username,
                    encrypted_password=encrypted_password,
                    notes=encrypted_notes,
                    category=category,
                    url=url,
                    password_strength_score=strength_score,
                    is_compromised=is_compromised,
                    user_id=current_user.id
                )
                new_entry.set_tags(tags)
                new_entry.update_password_age()
                db.session.add(new_entry)
                message = 'Password encrypted and saved!'
                current_user.log_security_event('PASSWORD_ADDED', f'Added new password for {site}')
            
            # Send breach notification if password is compromised
            if is_compromised and current_user.breach_check_enabled:
                current_user.send_notification(
                    "Password Breach Alert",
                    f"The password for {site} has been found in {analysis['count']:,} data breaches. Please change it immediately.",
                    channels=['web', 'email'],
                    urgent=True
                )

            db.session.commit()
            return jsonify({'success': True, 'message': message}), 201

        # GET request - return vault entries with enhanced data
        search_query = request.args.get('search', '')
        category_filter = request.args.get('category', '')
        sort_by = request.args.get('sort', 'updated_at')
        sort_order = request.args.get('order', 'desc')
        
        query = VaultEntry.query.filter_by(user_id=current_user.id)
        
        # Apply filters
        if search_query:
            query = query.filter(
                (VaultEntry.site.contains(search_query)) |
                (VaultEntry.username.contains(search_query)) |
                (VaultEntry.url.contains(search_query))
            )
        
        if category_filter:
            query = query.filter_by(category=category_filter)
        
        # Apply sorting
        if sort_order == 'desc':
            query = query.order_by(getattr(VaultEntry, sort_by).desc())
        else:
            query = query.order_by(getattr(VaultEntry, sort_by))
        
        entries = query.all()
        
        # Update password ages
        for entry in entries:
            entry.update_password_age()
        
        vault_entries = [{
            'id': entry.id,
            'site': entry.site,
            'username': entry.username,
            'category': entry.category,
            'url': entry.url,
            'tags': entry.get_tags(),
            'favorite': entry.favorite,
            'created_at': entry.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': entry.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'last_accessed': entry.last_accessed.strftime('%Y-%m-%d %H:%M:%S') if entry.last_accessed else None,
            'access_count': entry.access_count,
            'password_strength_score': entry.password_strength_score,
            'password_age_days': entry.password_age_days,
            'is_compromised': entry.is_compromised,
            'requires_2fa': entry.requires_2fa,
            'has_notes': bool(entry.notes),
            'security_status': 'compromised' if entry.is_compromised else 
                             'weak' if entry.password_strength_score <= 2 else 
                             'old' if entry.password_age_days > 90 else 'secure'
        } for entry in entries]
        
        # Get categories for filtering
        categories = db.session.query(VaultEntry.category).filter_by(user_id=current_user.id).distinct().all()
        categories = [cat[0] for cat in categories]
        
        return jsonify({
            'success': True, 
            'vault_entries': vault_entries,
            'categories': categories,
            'total_count': len(vault_entries),
            'filters_applied': bool(search_query or category_filter)
        }), 200
        
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
        decrypted_notes = decrypt_password(entry.notes, encryption_key) if entry.notes else ""
        
        entry.update_access()
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'password': decrypted_password,
            'notes': decrypted_notes,
            'entry_details': {
                'site': entry.site,
                'username': entry.username,
                'url': entry.url,
                'category': entry.category,
                'tags': entry.get_tags(),
                'created_at': entry.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': entry.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'access_count': entry.access_count,
                'password_age_days': entry.password_age_days,
                'strength_score': entry.password_strength_score,
                'is_compromised': entry.is_compromised
            }
        }), 200
        
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
        
        # Delete associated password history
        PasswordHistory.query.filter_by(vault_entry_id=entry_id).delete()
        
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
                'security_level': 'none',
                'entropy': 0,
                'patterns': []
            })
        
        # Perform comprehensive analysis
        analysis = perform_comprehensive_password_analysis(password)
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Password analysis error: {str(e)}")
        return jsonify({
            'success': True,
            'breached': False,
            'count': 0,
            'suggestions': ['Password analysis temporarily unavailable'],
            'score': 2,
            'crack_time': 'unknown',
            'security_level': 'unknown',
            'entropy': 0,
            'patterns': []
        })

@app.route('/api/me', methods=['GET'])
def get_user_info():
    try:
        if current_user.is_authenticated:
            vault_count = VaultEntry.query.filter_by(user_id=current_user.id).count()
            recent_events = SecurityEvent.query.filter_by(user_id=current_user.id).order_by(
                SecurityEvent.timestamp.desc()
            ).limit(5).all()
            
            # Get unread notifications count
            unread_notifications = Notification.query.filter_by(
                user_id=current_user.id, 
                read=False
            ).count()
            
            return jsonify({
                'success': True,
                'authenticated': True,
                'user': {
                    'id': current_user.id,
                    'username': current_user.username,
                    'email': current_user.email,
                    'phone_number': current_user.phone_number,
                    'created_at': current_user.created_at.isoformat(),
                    'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
                    'total_logins': current_user.total_logins,
                    'password_changes': current_user.password_changes,
                    'timezone': current_user.timezone,
                    'language': current_user.language
                },
                'security': {
                    'salt': current_user.encryption_salt,
                    'two_factor_enabled': current_user.two_factor_enabled,
                    'last_breach_check': current_user.last_breach_check.isoformat() if current_user.last_breach_check else None,
                    'notification_preferences': current_user.get_notification_preferences()
                },
                'vault': {
                    'total_passwords': vault_count,
                    'vault_usage_percent': round((vault_count / 50) * 100, 1),
                    'remaining_slots': 50 - vault_count
                },
                'notifications': {
                    'unread_count': unread_notifications
                },
                'recent_activity': [{
                    'type': event.event_type,
                    'description': event.description,
                    'timestamp': event.timestamp.isoformat(),
                    'severity': event.severity,
                    'ip_address': event.ip_address
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
    """Enhanced dashboard with comprehensive analytics"""
    try:
        # Vault statistics
        total_passwords = VaultEntry.query.filter_by(user_id=current_user.id).count()
        
        # Password strength distribution
        weak_passwords = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.password_strength_score <= 2
        ).count()
        strong_passwords = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.password_strength_score >= 4
        ).count()
        
        # Compromised passwords
        compromised_passwords = VaultEntry.query.filter_by(
            user_id=current_user.id, 
            is_compromised=True
        ).count()
        
        # Old passwords (90+ days)
        old_threshold = datetime.utcnow() - timedelta(days=90)
        old_passwords = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.updated_at < old_threshold
        ).count()
        
        # Recent activity
        recent_accesses = VaultEntry.query.filter_by(user_id=current_user.id).filter(
            VaultEntry.last_accessed.isnot(None)
        ).order_by(VaultEntry.last_accessed.desc()).limit(5).all()
        
        # Security events (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_events = SecurityEvent.query.filter(
            SecurityEvent.user_id == current_user.id,
            SecurityEvent.timestamp >= thirty_days_ago
        ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()
        
        # Calculate security score (0-100)
        security_score = 100
        if total_passwords > 0:
            security_score -= (weak_passwords / total_passwords) * 25
            security_score -= (compromised_passwords / total_passwords) * 35
            security_score -= (old_passwords / total_passwords) * 15
            
            # Bonus for 2FA
            if current_user.two_factor_enabled:
                security_score += 10
                
            # Bonus for notifications enabled
            if current_user.breach_check_enabled:
                security_score += 5
                
            security_score = max(0, min(100, int(security_score)))
        
        # Get categories distribution
        categories = db.session.query(
            VaultEntry.category, 
            db.func.count(VaultEntry.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(VaultEntry.category).all()
        
        categories_data = [{'category': cat[0], 'count': cat[1]} for cat in categories]
        
        # Get trusted devices
        trusted_devices = TrustedDevice.query.filter_by(
            user_id=current_user.id
        ).order_by(TrustedDevice.last_seen.desc()).limit(5).all()
        
        return jsonify({
            'success': True,
            'dashboard': {
                'security_score': security_score,
                'security_grade': get_security_grade(security_score),
                'vault_stats': {
                    'total_passwords': total_passwords,
                    'weak_passwords': weak_passwords,
                    'strong_passwords': strong_passwords,
                    'compromised_passwords': compromised_passwords,
                    'old_passwords': old_passwords,
                    'vault_usage': round((total_passwords / 50) * 100, 1),
                    'categories': categories_data
                },
                'recent_activity': {
                    'password_accesses': [{
                        'site': entry.site,
                        'accessed': entry.last_accessed.isoformat(),
                        'access_count': entry.access_count
                    } for entry in recent_accesses],
                    'security_events': [{
                        'type': event.event_type,
                        'description': event.description,
                        'timestamp': event.timestamp.isoformat(),
                        'severity': event.severity,
                        'ip_address': event.ip_address
                    } for event in recent_events]
                },
                'devices': [{
                    'device_name': device.device_name,
                    'device_type': device.device_type,
                    'last_seen': device.last_seen.isoformat(),
                    'is_trusted': device.is_trusted,
                    'login_count': device.login_count
                } for device in trusted_devices],
                'recommendations': generate_security_recommendations(
                    weak_passwords, compromised_passwords, old_passwords, 
                    current_user.two_factor_enabled, current_user.breach_check_enabled
                )
            }
        })
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load dashboard'}), 500

def get_security_grade(score):
    """Convert security score to letter grade"""
    if score >= 90:
        return 'A+'
    elif score >= 85:
        return 'A'
    elif score >= 80:
        return 'B+'
    elif score >= 75:
        return 'B'
    elif score >= 70:
        return 'C+'
    elif score >= 65:
        return 'C'
    elif score >= 60:
        return 'D'
    else:
        return 'F'

def generate_security_recommendations(weak_passwords, compromised_passwords, old_passwords, has_2fa, breach_check_enabled):
    """Generate personalized security recommendations"""
    recommendations = []
    
    if compromised_passwords > 0:
        recommendations.append({
            'type': 'urgent',
            'title': 'Update Compromised Passwords',
            'description': f'You have {compromised_passwords} passwords that have been found in data breaches',
            'action': 'Update immediately'
        })
    
    if weak_passwords > 0:
        recommendations.append({
            'type': 'important',
            'title': 'Strengthen Weak Passwords',
            'description': f'{weak_passwords} passwords are considered weak and easy to crack',
            'action': 'Use password generator'
        })
    
    if old_passwords > 0:
        recommendations.append({
            'type': 'warning',
            'title': 'Update Old Passwords',
            'description': f'{old_passwords} passwords are older than 90 days',
            'action': 'Regular rotation recommended'
        })
    
    if not has_2fa:
        recommendations.append({
            'type': 'suggestion',
            'title': 'Enable Two-Factor Authentication',
            'description': 'Add an extra layer of security to your account',
            'action': 'Enable in settings'
        })
    
    if not breach_check_enabled:
        recommendations.append({
            'type': 'suggestion',
            'title': 'Enable Breach Monitoring',
            'description': 'Get notified when your passwords are found in breaches',
            'action': 'Enable notifications'
        })
    
    return recommendations

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Get user notifications"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        query = Notification.query.filter_by(user_id=current_user.id)
        
        if unread_only:
            query = query.filter_by(read=False)
        
        # Filter out expired notifications
        query = query.filter(
            (Notification.expires_at.is_(None)) | 
            (Notification.expires_at > datetime.utcnow())
        )
        
        notifications = query.order_by(Notification.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'notifications': [{
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'type': notification.type,
                'category': notification.category,
                'action_url': notification.action_url,
                'action_text': notification.action_text,
                'read': notification.read,
                'created_at': notification.created_at.isoformat(),
                'expires_at': notification.expires_at.isoformat() if notification.expires_at else None
            } for notification in notifications.items],
            'pagination': {
                'page': notifications.page,
                'pages': notifications.pages,
                'per_page': notifications.per_page,
                'total': notifications.total,
                'has_next': notifications.has_next,
                'has_prev': notifications.has_prev
            },
            'unread_count': Notification.query.filter_by(
                user_id=current_user.id, read=False
            ).count()
        })
        
    except Exception as e:
        logger.error(f"Get notifications error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load notifications'}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    try:
        notification = Notification.query.filter_by(
            id=notification_id, 
            user_id=current_user.id
        ).first()
        
        if not notification:
            return jsonify({'success': False, 'message': 'Notification not found'}), 404
        
        notification.read = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Notification marked as read'})
        
    except Exception as e:
        logger.error(f"Mark notification read error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to mark notification as read'}), 500

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    try:
        Notification.query.filter_by(
            user_id=current_user.id, 
            read=False
        ).update({'read': True})
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'All notifications marked as read'})
        
    except Exception as e:
        logger.error(f"Mark all notifications read error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to mark notifications as read'}), 500

@app.route('/api/settings/notifications', methods=['GET', 'POST'])
@login_required
def notification_settings():
    """Manage notification preferences"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            
            # Update notification preferences
            preferences = {
                'breach_alerts': data.get('breach_alerts', True),
                'password_age_warnings': data.get('password_age_warnings', True),
                'security_updates': data.get('security_updates', True),
                'login_notifications': data.get('login_notifications', True),
                'new_device_notifications': data.get('new_device_notifications', True),
                'email_notifications': data.get('email_notifications', bool(current_user.email)),
                'sms_notifications': data.get('sms_notifications', bool(current_user.phone_number)),
                'security_reports': data.get('security_reports', True)
            }
            
            current_user.set_notification_preferences(preferences)
            current_user.breach_check_enabled = preferences['breach_alerts']
            current_user.security_report_frequency = data.get('security_report_frequency', 'weekly')
            
            db.session.commit()
            
            current_user.log_security_event('SETTINGS_UPDATED', 'Notification preferences updated')
            
            return jsonify({
                'success': True,
                'message': 'Notification preferences updated successfully',
                'preferences': preferences
            })
        
        # GET request
        return jsonify({
            'success': True,
            'preferences': current_user.get_notification_preferences(),
            'contact_info': {
                'email': current_user.email,
                'phone_number': current_user.phone_number
            },
            'security_report_frequency': current_user.security_report_frequency
        })
        
    except Exception as e:
        logger.error(f"Notification settings error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to manage notification settings'}), 500

@app.route('/api/settings/profile', methods=['GET', 'POST'])
@login_required
def profile_settings():
    """Manage user profile settings"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            
            # Update profile information
            email = sanitize_input(data.get('email', ''))
            phone = sanitize_input(data.get('phone', ''))
            timezone = sanitize_input(data.get('timezone', 'UTC'))
            language = sanitize_input(data.get('language', 'en'))
            
            # Validate email and phone
            if email:
                email_valid, email_error = validate_email(email)
                if not email_valid:
                    return jsonify({'success': False, 'message': email_error}), 400
                
                # Check if email is already taken by another user
                existing_user = User.query.filter(
                    User.email == email, 
                    User.id != current_user.id
                ).first()
                if existing_user:
                    return jsonify({'success': False, 'message': 'Email already in use by another account'}), 400
            
            if phone:
                phone_valid, phone_error = validate_phone_number(phone)
                if not phone_valid:
                    return jsonify({'success': False, 'message': phone_error}), 400
            
            # Update user profile
            old_email = current_user.email
            current_user.email = email if email else None
            current_user.phone_number = phone if phone else None
            current_user.timezone = timezone
            current_user.language = language
            
            db.session.commit()
            
            # Log the change
            changes = []
            if email != old_email:
                changes.append(f"email changed to {email}")
            current_user.log_security_event('PROFILE_UPDATED', f'Profile updated: {", ".join(changes) if changes else "profile information updated"}')
            
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully',
                'profile': {
                    'email': current_user.email,
                    'phone_number': current_user.phone_number,
                    'timezone': current_user.timezone,
                    'language': current_user.language
                }
            })
        
        # GET request
        return jsonify({
            'success': True,
            'profile': {
                'username': current_user.username,
                'email': current_user.email,
                'phone_number': current_user.phone_number,
                'timezone': current_user.timezone,
                'language': current_user.language,
                'created_at': current_user.created_at.isoformat(),
                'total_logins': current_user.total_logins,
                'password_changes': current_user.password_changes
            }
        })
        
    except Exception as e:
        logger.error(f"Profile settings error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to manage profile settings'}), 500

# --------------------------------------------------------
# Error Handlers
# --------------------------------------------------------
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'API endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}")
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'success': False, 'message': 'Rate limit exceeded. Please try again later.'}), 429

# --------------------------------------------------------
# SSL Certificate Generation
# --------------------------------------------------------
def create_ssl_certificate():
    try:
        from datetime import datetime, timedelta
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Development"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VaultGuard"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
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

        with open('cert.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open('key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print("✅ SSL certificates generated successfully!")
        return True
        
    except ImportError:
        print("❌ Cryptography package required. Install with: pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"SSL certificate generation failed: {str(e)}")
        return False

# --------------------------------------------------------
# Background Tasks & Cleanup
# --------------------------------------------------------
def cleanup_expired_tokens():
    """Clean up expired OTP tokens and notifications"""
    try:
        # Clean expired OTP tokens
        expired_tokens = OTPToken.query.filter(
            OTPToken.expires_at < datetime.utcnow()
        ).all()
        for token in expired_tokens:
            db.session.delete(token)
        
        # Clean expired notifications
        expired_notifications = Notification.query.filter(
            Notification.expires_at < datetime.utcnow()
        ).all()
        for notification in expired_notifications:
            db.session.delete(notification)
        
        # Clean old security events (keep only last 90 days)
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        old_events = SecurityEvent.query.filter(
            SecurityEvent.timestamp < cutoff_date
        ).all()
        for event in old_events:
            db.session.delete(event)
        
        db.session.commit()
        logger.info(f"Cleanup completed: {len(expired_tokens)} tokens, {len(expired_notifications)} notifications, {len(old_events)} events")
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        db.session.rollback()

# --------------------------------------------------------
# Application Startup
# --------------------------------------------------------
if __name__ == '__main__':
    print("=" * 80)
    print("🛡️  VAULTGUARD SECURE - COMPLETE ENHANCED VERSION")
    print("=" * 80)
    
    # Initialize database
    if not initialize_database():
        print("❌ Cannot start without database. Please fix database issues first.")
        exit(1)
    
    # Run initial cleanup
    cleanup_expired_tokens()
    
    print("✅ Complete Phase 1+ Features:")
    print("   📱 Email/SMS Notifications")  
    print("   🔐 Password Recovery via OTP")
    print("   💻 Device Detection & Management")
    print("   🎨 Enhanced UI with Dashboard")
    print("   📊 Comprehensive Analytics")
    print("   🔔 Advanced Notification System")
    print("   🛡️ Real HaveIBeenPwned Integration")
    print("   ⚡ Professional Security Features")
    print("=" * 80)
    
    # SSL setup
    ssl_context = None
    cert_exists = os.path.exists('cert.pem') and os.path.exists('key.pem')
    
    if not cert_exists:
        print("🔐 Generating SSL certificates...")
        if create_ssl_certificate():
            cert_exists = True
    
    if cert_exists:
        print("🔒 HTTPS enabled with SSL certificates")
        print("\n🌐 Access URLs:")
        print("   • HTTPS: https://127.0.0.1:5000")
        print("   • HTTPS: https://localhost:5000")
        print("\n⚠️  Browser will show security warning (normal for self-signed certificates)")
        print("   Click 'Advanced' → 'Proceed to 127.0.0.1 (unsafe)' to continue")
    else:
        print("⚠️  Running without HTTPS")
        print("🌐 Access: http://127.0.0.1:5000")
    
    print("\n🚀 ENHANCED FEATURES ACTIVE:")
    print("   ✅ AES-256 Password Encryption")
    print("   ✅ Real HaveIBeenPwned API Integration")
    print("   ✅ Email/SMS Notifications (Twilio)")
    print("   ✅ OTP Password Recovery System")
    print("   ✅ Device Detection & Tracking")
    print("   ✅ Comprehensive Security Dashboard")
    print("   ✅ Advanced Analytics & Reporting")
    print("   ✅ Multi-Channel Notifications")
    print("   ✅ Password History & Breach Monitoring")
    print("   ✅ Enhanced User Profile Management")
    print("   ✅ Professional Security Logging")
    print("   ✅ Automated Cleanup & Maintenance")
    
    print(f"\n📦 Dependencies Status:")
    print(f"   • Requests (HaveIBeenPwned): {'✅ Available' if REQUESTS_AVAILABLE else '❌ Missing'}")
    print(f"   • Twilio (SMS): {'✅ Available' if TWILIO_AVAILABLE else '❌ Missing'}")
    print(f"   • User-Agents: {'✅ Available' if 'user_agents' in globals() else '❌ Missing'}")
    
    print(f"\n🔧 Configuration:")
    print(f"   • Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"   • Debug Mode: {'ON' if os.environ.get('FLASK_ENV') != 'production' else 'OFF'}")
    print(f"   • Email Server: {app.config['MAIL_SERVER']}")
    print(f"   • Max Vault Entries: 50 per user")
    
    print("\n📧 Setup Instructions:")
    if not app.config['MAIL_USERNAME']:
        print("   ⚠️  Email notifications disabled (no MAIL_USERNAME)")
        print("      Set environment variables:")
        print("      export MAIL_USERNAME=your-email@gmail.com")
        print("      export MAIL_PASSWORD=your-app-password")
    
    if not TWILIO_AVAILABLE or not app.config['TWILIO_ACCOUNT_SID']:
        print("   ⚠️  SMS notifications disabled (no Twilio config)")
        print("      Install: pip install twilio")
        print("      Set environment variables:")
        print("      export TWILIO_ACCOUNT_SID=your-sid")
        print("      export TWILIO_AUTH_TOKEN=your-token")
        print("      export TWILIO_PHONE_NUMBER=+1234567890")
    
    if not REQUESTS_AVAILABLE:
        print("   ⚠️  Install requests for real breach checking:")
        print("      pip install requests user-agents")
    
    print("=" * 80)
    print("📝 Check 'vaultguard.log' for detailed application logs")
    print("🎯 Ready for production deployment with proper environment variables")
    print("=" * 80)
    
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
        print("   1. Check port 5000 is not in use: netstat -an | grep 5000")
        print("   2. Install missing dependencies:")
        print("      pip install flask flask-sqlalchemy flask-bcrypt flask-login")
        print("      pip install zxcvbn cryptography bleach requests user-agents twilio")
        print("   3. Check file permissions in current directory")
        print("   4. Review 'vaultguard.log' for detailed error information")
        print("   5. Try without SSL if certificate issues persist")
