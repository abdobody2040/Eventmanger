#!/usr/bin/env python3
"""
PharmaEvents - Minimal Flask Application
"""

import os
import io
import csv
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✓ Loaded environment variables from .env file")
except ImportError:
    print("⚠ python-dotenv not installed, using system environment variables")

# Egyptian governorates list
egyptian_governorates = [
    'Cairo', 'Giza', 'Alexandria', 'Dakahlia', 'Red Sea', 'Beheira', 'Fayoum',
    'Gharbiya', 'Ismailia', 'Menofia', 'Minya', 'Qaliubiya', 'New Valley',
    'Suez', 'Aswan', 'Assiut', 'Beni Suef', 'Port Said', 'Damietta',
    'Sharkia', 'South Sinai', 'Kafr El Sheikh', 'Matrouh', 'Luxor',
    'Qena', 'North Sinai', 'Sohag'
]

# Validate required environment variables
required_env_vars = ["DATABASE_URL", "SESSION_SECRET", "ADMIN_EMAIL", "ADMIN_PASSWORD"]
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}. Please check your .env file.")

# Create app with configuration from .env
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.config['REMEMBER_COOKIE_HTTPONLY'] = os.environ.get('REMEMBER_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['WTF_CSRF_TIME_LIMIT'] = int(os.environ.get('CSRF_TIME_LIMIT', '3600'))
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_SIZE', '16777216'))  # 16MB default
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database - PostgreSQL only from .env
database_url = os.environ.get("DATABASE_URL")
if not database_url or not database_url.startswith(('postgresql://', 'postgres://')):
    raise RuntimeError("DATABASE_URL must be a PostgreSQL connection string")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'False').lower() == 'true'
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": int(os.environ.get('DB_POOL_SIZE', '20')),
    "max_overflow": int(os.environ.get('DB_MAX_OVERFLOW', '50')),
    "pool_timeout": int(os.environ.get('DB_POOL_TIMEOUT', '10')),
    "pool_recycle": int(os.environ.get('DB_POOL_RECYCLE', '3600')),
    "pool_pre_ping": os.environ.get('DB_POOL_PRE_PING', 'True').lower() == 'true',
    "pool_reset_on_return": os.environ.get('DB_POOL_RESET_ON_RETURN', 'commit'),
    "connect_args": {
        "options": "-c statement_timeout=30000 -c lock_timeout=10000 -c idle_in_transaction_session_timeout=300000",
        "connect_timeout": 30
    }
}

# Initialize database
db = SQLAlchemy(app)

# Initialize caching
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',  # Use simple in-memory cache for development
    'CACHE_DEFAULT_TIMEOUT': int(os.environ.get('CACHE_TIMEOUT', '300'))  # 5 minutes default
})

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    headers_enabled=True
)

# Configure security logging
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
if not os.path.exists('logs'):
    os.makedirs('logs')
security_handler = RotatingFileHandler('logs/security.log', maxBytes=10240000, backupCount=10)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
security_logger.addHandler(security_handler)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

# User model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_event_manager(self):
        return self.role == 'event_manager'

    def is_medical_rep(self):
        return self.role == 'medical_rep'

    def can_approve_events(self):
        return self.role in ['admin', 'event_manager']

# App Settings model for persistent configuration
class AppSetting(db.Model):
    __tablename__ = 'app_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)

    @classmethod
    def get_setting(cls, key, default=None):
        try:
            setting = cls.query.filter_by(key=key).first()
            return setting.value if setting else default
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error getting setting {key}: {str(e)}')
            return default

    @classmethod
    def set_setting(cls, key, value):
        try:
            setting = cls.query.filter_by(key=key).first()
            if setting:
                setting.value = value
            else:
                setting = cls(key=key, value=value)
                db.session.add(setting)
            db.session.commit()
            return setting
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error setting {key}: {str(e)}')
            return None

# API Token model for API authentication
class APIToken(db.Model):
    __tablename__ = 'api_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(256), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='api_tokens')
    
    @classmethod
    def generate_token(cls, user_id, name):
        """Generate a new API token"""
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        api_token = cls(
            token_hash=token_hash,
            user_id=user_id,
            name=name
        )
        db.session.add(api_token)
        db.session.commit()
        return token, api_token
    
    @classmethod
    def verify_token(cls, token):
        """Verify an API token and return the associated user"""
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        api_token = cls.query.filter_by(token_hash=token_hash, is_active=True).first()
        if api_token:
            api_token.last_used = datetime.utcnow()
            db.session.commit()
            return api_token.user
        return None

# Security helper functions
def log_security_event(event_type, message, user_id=None, ip_address=None):
    """Log security events"""
    try:
        if not ip_address:
            ip_address = get_remote_address()
        
        user_info = f"User ID: {user_id}" if user_id else "Anonymous"
        security_logger.info(f"{event_type} - {message} - {user_info} - IP: {ip_address}")
    except Exception as e:
        app.logger.error(f"Error logging security event: {str(e)}")

def api_token_required(f):
    """Decorator for API endpoints requiring token authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            token = request.args.get('api_token')
        
        user = APIToken.verify_token(token)
        if not user:
            log_security_event("API_AUTH_FAILED", "Invalid or missing API token")
            return jsonify({'error': 'Invalid or missing API token'}), 401
        
        # Set current user for the request
        login_user(user)
        return f(*args, **kwargs)
    return decorated_function

def validate_file_size(file, max_size_mb=16):
    """Validate file size"""
    if file:
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        max_size_bytes = max_size_mb * 1024 * 1024
        if file_size > max_size_bytes:
            return False, f"File size exceeds {max_size_mb}MB limit"
    return True, "OK"

def validate_request_size():
    """Validate request content length"""
    max_size = app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB default
    if request.content_length and request.content_length > max_size:
        log_security_event("LARGE_REQUEST", f"Request size {request.content_length} exceeds limit {max_size}")
        abort(413)  # Request Entity Too Large

# Request size validation middleware
@app.before_request
def check_request_size():
    """Check request size before processing"""
    if request.content_length:
        max_size = app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)
        if request.content_length > max_size:
            log_security_event("LARGE_REQUEST_BLOCKED", f"Request size {request.content_length} exceeds limit")
            abort(413)

# Event Category model
class EventCategory(db.Model):
    __tablename__ = 'event_category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Event Type model
class EventType(db.Model):
    __tablename__ = 'event_type'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Association table for many-to-many relationship between events and categories
event_categories = db.Table('event_categories',
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('event_category.id'), primary_key=True)
)

# Event model
class Event(db.Model):
    __tablename__ = 'event'
    __table_args__ = (
        # Basic indexes for common queries
        db.Index('idx_event_start_datetime', 'start_datetime'),
        db.Index('idx_event_user_id', 'user_id'),
        db.Index('idx_event_status', 'status'),
        db.Index('idx_event_created_at', 'created_at'),
        db.Index('idx_event_is_online', 'is_online'),
        db.Index('idx_event_type_id', 'event_type_id'),
        db.Index('idx_event_end_datetime', 'end_datetime'),
        
        # Composite indexes for complex queries (order matters!)
        db.Index('idx_event_user_status', 'user_id', 'status'),
        db.Index('idx_event_user_start', 'user_id', 'start_datetime'),
        db.Index('idx_event_user_created', 'user_id', 'created_at'),
        db.Index('idx_event_start_status', 'start_datetime', 'status'),
        db.Index('idx_event_status_start', 'status', 'start_datetime'),
        db.Index('idx_event_user_online', 'user_id', 'is_online'),
        db.Index('idx_event_user_end', 'user_id', 'end_datetime'),
        
        # Index for export operations
        db.Index('idx_event_created_desc', 'created_at', postgresql_using='btree'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    event_type_id = db.Column(db.Integer, db.ForeignKey('event_type.id'))
    is_online = db.Column(db.Boolean, default=False)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime)
    registration_deadline = db.Column(db.DateTime, nullable=False)
    venue_id = db.Column(db.Integer, nullable=True)  # Could be linked to venue table later

    governorate = db.Column(db.String(100))
    image_file = db.Column(db.String(200), nullable=True)  # For storing event image filename
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, active, declined
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    event_type = db.relationship('EventType', backref='events')
    creator = db.relationship('User', backref='created_events')
    categories = db.relationship('EventCategory', secondary=event_categories, backref='events')

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error loading user {user_id}: {str(e)}')
        return None

def recover_db_session():
    """Recover from database transaction errors"""
    try:
        db.session.rollback()
        db.session.close()
    except Exception:
        pass

# Utility functions for performance optimization
def get_paginated_events(page=1, per_page=20, user_filter=None, order_by='created_at', desc=True, status_filter=None, search_query=None):
    """
    Get paginated events with optimized query and filtering.
    Returns tuple: (events, total_count, has_next, has_prev)
    """
    # Use optimized query with joinedload for related data
    query = Event.query.options(
        db.joinedload(Event.event_type),
        db.joinedload(Event.creator),
        db.joinedload(Event.categories)
    )
    
    # Apply filters
    if user_filter:
        query = query.filter(Event.user_id == user_filter)
    
    if status_filter and status_filter != 'all':
        query = query.filter(Event.status == status_filter)
    
    if search_query:
        # Use indexed search on name field
        query = query.filter(Event.name.ilike(f'%{search_query}%'))
    
    # Apply ordering using indexed columns
    if order_by == 'created_at':
        if desc:
            query = query.order_by(Event.created_at.desc())
        else:
            query = query.order_by(Event.created_at.asc())
    elif order_by == 'start_datetime':
        if desc:
            query = query.order_by(Event.start_datetime.desc())
        else:
            query = query.order_by(Event.start_datetime.asc())
    
    # Use optimized count query without loading all data
    from sqlalchemy import func
    total_count = db.session.query(func.count(Event.id)).filter(*[
        condition for condition in [
            Event.user_id == user_filter if user_filter else None,
            Event.status == status_filter if status_filter and status_filter != 'all' else None,
            Event.name.ilike(f'%{search_query}%') if search_query else None
        ] if condition is not None
    ]).scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    events = query.offset(offset).limit(per_page).all()
    
    # Calculate pagination info
    has_next = offset + per_page < total_count
    has_prev = page > 1
    
    return events, total_count, has_next, has_prev

@cache.memoize(timeout=300)  # Cache for 5 minutes
def get_dashboard_stats_cached(user_id, is_admin):
    """Get cached dashboard statistics"""
    from sqlalchemy import func, case
    now = datetime.now()
    
    # Single optimized query to get all counts
    if is_admin:
        stats = db.session.query(
            func.count(Event.id).label('total_events'),
            func.sum(case((Event.start_datetime > now, 1), else_=0)).label('upcoming_events'),
            func.sum(case((Event.is_online == True, 1), else_=0)).label('online_events'),
            func.sum(case((Event.status == 'pending', 1), else_=0)).label('pending_events'),
            func.sum(case((Event.end_datetime < now, 1), else_=0)).label('completed_events')
        ).first()
    else:
        stats = db.session.query(
            func.count(Event.id).label('total_events'),
            func.sum(case((Event.start_datetime > now, 1), else_=0)).label('upcoming_events'),
            func.sum(case((Event.is_online == True, 1), else_=0)).label('online_events'),
            func.sum(case((Event.status == 'pending', 1), else_=0)).label('pending_events'),
            func.sum(case((Event.end_datetime < now, 1), else_=0)).label('completed_events')
        ).filter(Event.user_id == user_id).first()
    
    return {
        'total_events': stats.total_events or 0,
        'upcoming_events': stats.upcoming_events or 0,
        'online_events': stats.online_events or 0,
        'offline_events': (stats.total_events or 0) - (stats.online_events or 0),
        'pending_events': stats.pending_events or 0,
        'completed_events': stats.completed_events or 0
    }

@cache.memoize(timeout=600)  # Cache for 10 minutes
def get_category_data_cached(user_id, is_admin):
    """Get cached category distribution data"""
    from sqlalchemy import func
    
    if is_admin:
        # Optimized query using database aggregation
        result = db.session.query(
            EventCategory.name,
            func.count(Event.id).label('count')
        ).join(
            event_categories, EventCategory.id == event_categories.c.category_id
        ).join(
            Event, event_categories.c.event_id == Event.id
        ).group_by(EventCategory.id, EventCategory.name).all()
    else:
        result = db.session.query(
            EventCategory.name,
            func.count(Event.id).label('count')
        ).join(
            event_categories, EventCategory.id == event_categories.c.category_id
        ).join(
            Event, event_categories.c.event_id == Event.id
        ).filter(Event.user_id == user_id).group_by(EventCategory.id, EventCategory.name).all()
    
    categories_data = [{'name': row[0], 'count': row[1]} for row in result if row[1] > 0]
    categories_data.sort(key=lambda x: x['count'], reverse=True)
    
    return categories_data

@cache.memoize(timeout=600)  # Cache for 10 minutes
def get_monthly_data_cached(user_id, is_admin):
    """Get cached monthly event distribution"""
    from sqlalchemy import func, extract
    current_year = datetime.now().year
    
    if is_admin:
        result = db.session.query(
            extract('month', Event.start_datetime).label('month'),
            func.count(Event.id).label('count')
        ).filter(
            extract('year', Event.start_datetime) == current_year
        ).group_by(extract('month', Event.start_datetime)).all()
    else:
        result = db.session.query(
            extract('month', Event.start_datetime).label('month'),
            func.count(Event.id).label('count')
        ).filter(
            Event.user_id == user_id,
            extract('year', Event.start_datetime) == current_year
        ).group_by(extract('month', Event.start_datetime)).all()
    
    # Initialize all months with 0
    monthly_counts = [0] * 12
    for month, count in result:
        if month:
            monthly_counts[int(month) - 1] = count
    
    return {
        'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        'data': monthly_counts
    }

@app.teardown_appcontext
def close_db_session(exception=None):
    """Ensure database sessions are properly closed"""
    try:
        if exception:
            db.session.rollback()
        else:
            db.session.commit()
    except Exception:
        db.session.rollback()
    finally:
        db.session.remove()

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    db.session.rollback()
    app.logger.error(f'Internal server error: {error}')
    flash('An internal error occurred. Please try again.', 'danger')
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    app.logger.warning(f'404 error: {error}')
    flash('The requested page was not found.', 'warning')
    return redirect(url_for('dashboard'))



# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Stricter rate limiting for login
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            log_security_event("LOGIN_ATTEMPT_FAILED", "Missing email or password", ip_address=get_remote_address())
            flash('Please enter both email and password', 'danger')
            app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
            theme_color = AppSetting.get_setting('theme_color', '#0f6e84')
            app_logo = AppSetting.get_setting('app_logo')
            return render_template('login.html', app_name=app_name, theme_color=theme_color, app_logo=app_logo)

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            log_security_event("LOGIN_SUCCESS", f"User {email} logged in successfully", user_id=user.id)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_security_event("LOGIN_FAILED", f"Failed login attempt for email: {email}", ip_address=get_remote_address())
            flash('Invalid email or password', 'danger')

    app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
    theme_color = AppSetting.get_setting('theme_color', '#0f6e84')
    app_logo = AppSetting.get_setting('app_logo')
    main_tagline = AppSetting.get_setting('main_tagline')
    main_header = AppSetting.get_setting('main_header')
    app_description = AppSetting.get_setting('app_description')
    feature1_title = AppSetting.get_setting('feature1_title')
    feature1_description = AppSetting.get_setting('feature1_description')
    feature2_title = AppSetting.get_setting('feature2_title')
    feature2_description = AppSetting.get_setting('feature2_description')
    return render_template('login.html', 
                         app_name=app_name, 
                         theme_color=theme_color,
                         app_logo=app_logo,
                         main_tagline=main_tagline,
                         main_header=main_header,
                         app_description=app_description,
                         feature1_title=feature1_title,
                         feature1_description=feature1_description,
                         feature2_title=feature2_title,
                         feature2_description=feature2_description)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get app settings
    app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
    theme_color = AppSetting.get_setting('theme_color', '#0f6e84')

    # Get filter parameters
    search_query = request.args.get('search', '').strip()
    category_filter = request.args.get('category', 'all')
    type_filter = request.args.get('type', 'all')
    date_filter = request.args.get('date', 'all')

    # Get categories and event types for filter dropdowns
    try:
        categories = EventCategory.query.all()
        event_types = EventType.query.all()
    except Exception as e:
        app.logger.error(f'Error fetching categories/types: {str(e)}')
        categories = []
        event_types = []

    # Use cached dashboard statistics for better performance
    try:
        now = datetime.now()
        
        # Get cached stats (apply filters for statistics)
        stats = get_filtered_dashboard_stats(
            user_id=current_user.id,
            is_admin=current_user.can_approve_events(),
            search_query=search_query,
            category_filter=category_filter,
            type_filter=type_filter,
            date_filter=date_filter
        )
        
        total_events = stats['total_events']
        upcoming_events = stats['upcoming_events']
        online_events = stats['online_events']
        offline_events = stats['offline_events']
        pending_events_count = stats['pending_events']

        # Apply filters to recent and upcoming events
        if current_user.can_approve_events():
            recent_query = Event.query.options(
                db.joinedload(Event.event_type),
                db.joinedload(Event.categories)
            )
            upcoming_query = Event.query.filter(Event.start_datetime > now).options(
                db.joinedload(Event.event_type),
                db.joinedload(Event.categories)
            )
        else:
            recent_query = Event.query.filter_by(user_id=current_user.id).options(
                db.joinedload(Event.event_type),
                db.joinedload(Event.categories)
            )
            upcoming_query = Event.query.filter(Event.user_id == current_user.id, Event.start_datetime > now).options(
                db.joinedload(Event.event_type),
                db.joinedload(Event.categories)
            )

        # Apply search filter
        if search_query:
            search_filter = db.or_(
                Event.name.ilike(f'%{search_query}%'),
                Event.description.ilike(f'%{search_query}%'),
                Event.location.ilike(f'%{search_query}%')
            )
            recent_query = recent_query.filter(search_filter)
            upcoming_query = upcoming_query.filter(search_filter)

        # Apply category filter
        if category_filter != 'all':
            try:
                category_id = int(category_filter)
                recent_query = recent_query.filter(Event.categories.any(EventCategory.id == category_id))
                upcoming_query = upcoming_query.filter(Event.categories.any(EventCategory.id == category_id))
            except (ValueError, TypeError):
                pass

        # Apply event type filter
        if type_filter != 'all':
            try:
                type_id = int(type_filter)
                recent_query = recent_query.filter_by(event_type_id=type_id)
                upcoming_query = upcoming_query.filter_by(event_type_id=type_id)
            except (ValueError, TypeError):
                pass

        # Apply date filter
        if date_filter == 'upcoming':
            recent_query = recent_query.filter(Event.start_datetime > now)
        elif date_filter == 'past':
            recent_query = recent_query.filter(Event.start_datetime < now)
            upcoming_query = upcoming_query.filter(Event.start_datetime < now)
        elif date_filter == 'this_month':
            start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
            recent_query = recent_query.filter(Event.start_datetime >= start_of_month, Event.start_datetime <= end_of_month)
            upcoming_query = upcoming_query.filter(Event.start_datetime >= start_of_month, Event.start_datetime <= end_of_month)
        elif date_filter == 'last_month':
            first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            first_of_last_month = (first_of_this_month - timedelta(days=1)).replace(day=1)
            last_of_last_month = first_of_this_month - timedelta(seconds=1)
            recent_query = recent_query.filter(Event.start_datetime >= first_of_last_month, Event.start_datetime <= last_of_last_month)
            upcoming_query = upcoming_query.filter(Event.start_datetime >= first_of_last_month, Event.start_datetime <= last_of_last_month)

        recent_events = recent_query.order_by(Event.created_at.desc()).limit(5).all()
        upcoming_events_list = upcoming_query.order_by(Event.start_datetime.asc()).limit(5).all()

        # Get filtered chart data
        category_data = get_filtered_category_data(current_user.id, current_user.can_approve_events(), search_query, category_filter, type_filter, date_filter)
        event_type_data = get_filtered_type_data(current_user.id, current_user.can_approve_events(), search_query, category_filter, type_filter, date_filter)

    except Exception as e:
        app.logger.error(f'Error calculating dashboard stats: {str(e)}')
        # Fallback values
        total_events = 0
        upcoming_events = 0
        online_events = 0
        offline_events = 0
        pending_events_count = 0
        recent_events = []
        upcoming_events_list = []
        category_data = []
        event_type_data = []

    app_logo = AppSetting.get_setting('app_logo')
    return render_template('dashboard.html', 
                         app_name=app_name,
                         app_logo=app_logo,
                         theme_color=theme_color,
                         total_events=total_events,
                         upcoming_events=upcoming_events,  
                         online_events=online_events,
                         offline_events=offline_events,
                         pending_events_count=pending_events_count,
                         recent_events=recent_events,
                         upcoming_events_list=upcoming_events_list,
                         category_data=category_data,
                         event_type_data=event_type_data,
                         categories=categories,
                         event_types=event_types,
                         search_query=search_query,
                         selected_category=category_filter,
                         selected_type=type_filter,
                         selected_date=date_filter)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/events')
@login_required
def events():
    # Get common settings in a single batch query optimized call
    settings_keys = ['app_name', 'theme_color', 'app_logo']
    settings = {}
    try:
        for key in settings_keys:
            settings[key] = AppSetting.get_setting(key, 'PharmaEvents' if key == 'app_name' else '#0f6e84' if key == 'theme_color' else None)
    except Exception as e:
        app.logger.error(f'Error fetching settings: {str(e)}')
        settings = {'app_name': 'PharmaEvents', 'theme_color': '#0f6e84', 'app_logo': None}

    # Simplified category and event type loading
    try:
        categories = EventCategory.query.order_by(EventCategory.name).all()
        event_types = EventType.query.order_by(EventType.name).all()
    except Exception as e:
        app.logger.error(f'Error fetching categories/types: {str(e)}')
        categories = []
        event_types = []

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
    
    # Search and filter parameters
    search_query = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'all')
    category_filter = request.args.get('category', 'all')
    type_filter = request.args.get('type', 'all')
    date_filter = request.args.get('date', 'all')
    
    # Build query with filters
    try:
        if current_user.can_approve_events():
            query = Event.query.options(
                db.joinedload(Event.event_type),
                db.joinedload(Event.categories)
            )
        else:
            query = Event.query.filter_by(user_id=current_user.id).options(
                db.joinedload(Event.event_type),
                db.joinedload(Event.categories)
            )
        
        # Apply search filter (search in name, description, and location)
        if search_query:
            query = query.filter(
                db.or_(
                    Event.name.ilike(f'%{search_query}%'),
                    Event.description.ilike(f'%{search_query}%'),
                    Event.location.ilike(f'%{search_query}%')
                )
            )
        
        # Apply status filter
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
            
        # Apply category filter
        if category_filter != 'all':
            try:
                category_id = int(category_filter)
                query = query.filter(Event.categories.any(EventCategory.id == category_id))
            except (ValueError, TypeError):
                pass
                
        # Apply event type filter
        if type_filter != 'all':
            try:
                type_id = int(type_filter)
                query = query.filter_by(event_type_id=type_id)
            except (ValueError, TypeError):
                pass
                
        # Apply date filter
        if date_filter == 'upcoming':
            query = query.filter(Event.start_datetime > datetime.utcnow())
        elif date_filter == 'past':
            query = query.filter(Event.start_datetime < datetime.utcnow())
        
        # Paginate results
        events_pagination = query.order_by(Event.start_datetime.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        events = events_pagination.items
        
    except Exception as e:
        app.logger.error(f'Error fetching events: {str(e)}')
        events = []
        events_pagination = None

    return render_template('events.html', 
                         app_name=settings['app_name'],
                         app_logo=settings['app_logo'],
                         theme_color=settings['theme_color'],
                         events=events, 
                         categories=categories,
                         event_types=event_types,
                         search_query=search_query,
                         selected_status=status_filter,
                         selected_category=category_filter,
                         selected_type=type_filter,
                         selected_date=date_filter,
                         events_pagination=events_pagination)

@app.route('/event_details/<int:event_id>')
@login_required
def event_details(event_id):
    """Display detailed information about a specific event"""
    try:
        event = Event.query.get_or_404(event_id)
        app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
        theme_color = AppSetting.get_setting('theme_color', '#0f6e84')
        app_logo = AppSetting.get_setting('app_logo')

        return render_template('event_details.html',
                             app_name=app_name,
                             app_logo=app_logo, 
                             theme_color=theme_color,
                             event=event)
    except Exception as e:
        app.logger.error(f'Error loading event details: {str(e)}')
        flash('Event not found or error loading details.', 'danger')
        return redirect(url_for('events'))

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour")  # Rate limit event creation
def create_event():
    app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
    theme_color = AppSetting.get_setting('theme_color', '#0f6e84')

    # Get categories from database
    try:
        categories = EventCategory.query.order_by(EventCategory.name).all()
    except Exception as e:
        app.logger.error(f'Error fetching categories: {str(e)}')
        categories = []

    # Get event types from database
    try:
        event_types = EventType.query.order_by(EventType.name).all()
    except Exception as e:
        app.logger.error(f'Error fetching event types: {str(e)}')
        event_types = []

    if request.method == 'POST':
        # Handle event creation
        try:
            # Get form data
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            event_type_id = request.form.get('event_type')
            category_id = request.form.get('categories')
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            start_time = request.form.get('start_time')
            end_time = request.form.get('end_time')
            registration_deadline_date = request.form.get('registration_deadline_date')
            registration_deadline_time = request.form.get('registration_deadline_time')
            is_online = request.form.get('is_online') == 'on'
            venue = request.form.get('venue', '').strip() if not is_online else None
            governorate = request.form.get('governorate', '').strip() if not is_online else None
            max_attendees = request.form.get('max_attendees')

            # Handle attendees file upload (now required)
            attendees_file = request.files.get('attendees_file')
            attendees_filename = None
            attendees_count = 0

            # Check if attendees file is provided (required)
            if not attendees_file or not attendees_file.filename:
                log_security_event("FILE_UPLOAD_FAILED", "Missing attendees file", user_id=current_user.id)
                flash('Attendees list file is required. Please upload a CSV or Excel file with attendee details.', 'danger')
                app_logo = AppSetting.get_setting('app_logo')
                return render_template('create_event.html', 
                                     app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                     categories=categories, event_types=event_types, 
                                     governorates=egyptian_governorates, edit_mode=False)

            if attendees_file and attendees_file.filename:
                # Validate file size first
                size_valid, size_message = validate_file_size(attendees_file, max_size_mb=5)
                if not size_valid:
                    log_security_event("FILE_UPLOAD_FAILED", f"Attendees file too large: {size_message}", user_id=current_user.id)
                    flash(size_message, 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

                # Validate file type (CSV, Excel)
                allowed_extensions = {'csv', 'xlsx', 'xls'}
                file_ext = attendees_file.filename.rsplit('.', 1)[1].lower() if '.' in attendees_file.filename else ''
                if file_ext not in allowed_extensions:
                    log_security_event("FILE_UPLOAD_FAILED", f"Invalid attendees file type: {file_ext}", user_id=current_user.id)
                    flash('Attendees file must be CSV or Excel format', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

                # Save the file with error handling
                try:
                    upload_folder = os.path.join(app.static_folder or 'static', 'uploads', 'attendees')
                    os.makedirs(upload_folder, exist_ok=True)
                    attendees_filename = f"attendees_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{attendees_file.filename}"
                    file_path = os.path.join(upload_folder, attendees_filename)
                    attendees_file.save(file_path)
                except OSError as e:
                    app.logger.error(f'File save error: {str(e)}')
                    flash('Error saving attendees file. Please try again.', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

                # Process and validate the attendees file
                try:
                    if file_ext == 'csv':
                        df = pd.read_csv(file_path)
                    else:  # xlsx or xls
                        df = pd.read_excel(file_path)

                    # Flexible validation - just check if file has data
                    if df.empty:
                        flash('Attendees file appears to be empty', 'danger')
                        os.remove(file_path)  # Clean up the uploaded file
                        app_logo = AppSetting.get_setting('app_logo')
                        return render_template('create_event.html', 
                                             app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                             categories=categories, event_types=event_types, 
                                             governorates=egyptian_governorates, edit_mode=False)

                    # Count valid attendees (rows with non-null values in key columns)
                    # Look for columns that might contain names or emails
                    name_cols = [col for col in df.columns if any(keyword in col.lower() for keyword in ['name', 'participant', 'attendee'])]
                    email_cols = [col for col in df.columns if 'email' in col.lower() or 'mail' in col.lower()]

                    if name_cols:
                        attendees_count = len(df.dropna(subset=name_cols[:1]))  # Use first name column
                    else:
                        attendees_count = len(df.dropna())  # Count all non-empty rows

                    app.logger.info(f'Processed attendees file with {attendees_count} attendees from {len(df)} total rows')
                    app.logger.info(f'File columns: {list(df.columns)}')

                except Exception as e:
                    app.logger.error(f'Error processing attendees file: {str(e)}')
                    flash('Error processing attendees file. Please check the format and try again.', 'danger')
                    if os.path.exists(file_path):
                        os.remove(file_path)  # Clean up the uploaded file
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

            # Basic validation
            app.logger.info(f'Form data received - Title: "{title}", Description: "{description}", Start Date: "{start_date}"')

            validation_errors = []

            if not title:
                validation_errors.append('Event title is required')
            if not description:
                validation_errors.append('Event description is required')
            if not start_date:
                validation_errors.append('Start date is required')
            if not end_date:
                validation_errors.append('End date is required')
            if not end_time:
                validation_errors.append('End time is required')
            # Validation for new required fields
            venue = request.form.get('venue', '').strip()
            service_request = request.form.get('service_request', '').strip()
            employee_code = request.form.get('employee_code', '').strip()
            
            if not is_online and not venue:
                validation_errors.append('Venue name is required for offline events')
            if not service_request:
                validation_errors.append('Service Request ID is required')
            if not employee_code:
                validation_errors.append('Employee Code is required')
            
            if not registration_deadline_date:
                validation_errors.append('Registration deadline date is required')
            if not registration_deadline_time:
                validation_errors.append('Registration deadline time is required')
            if not is_online and not governorate:
                validation_errors.append('Governorate is required for offline events')

            if validation_errors:
                for error in validation_errors:
                    flash(error, 'danger')
                app_logo = AppSetting.get_setting('app_logo')
                return render_template('create_event.html', 
                                     app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                     categories=categories, event_types=event_types, 
                                     governorates=egyptian_governorates, edit_mode=False)

            # Combine date and time for datetime fields with error handling
            start_datetime = None
            end_datetime = None
            registration_deadline = None

            try:
                if start_date:
                    if start_time:
                        start_datetime = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
                    else:
                        start_datetime = datetime.strptime(start_date, "%Y-%m-%d")

                if end_date:
                    if end_time:
                        end_datetime = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M")
                    else:
                        end_datetime = datetime.strptime(end_date, "%Y-%m-%d")

                if registration_deadline_date and registration_deadline_time:
                    registration_deadline = datetime.strptime(f"{registration_deadline_date} {registration_deadline_time}", "%Y-%m-%d %H:%M")
                elif registration_deadline_date:
                    registration_deadline = datetime.strptime(registration_deadline_date, "%Y-%m-%d")
                else:
                    # Default to start date if not provided (fallback)
                    registration_deadline = start_datetime

                # Validate datetime logic
                if start_datetime and end_datetime and end_datetime <= start_datetime:
                    flash('End date must be after start date', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

                # Update validation: registration deadline can now be after event end date (2 days after)
                # Remove the old validation that required registration deadline to be before start date
                pass

            except ValueError as e:
                flash(f'Invalid date/time format: {str(e)}', 'danger')
                app_logo = AppSetting.get_setting('app_logo')
                return render_template('create_event.html', 
                                     app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                     categories=categories, event_types=event_types, 
                                     governorates=egyptian_governorates, edit_mode=False)

            # Handle optional image upload
            image_filename = None
            event_image = request.files.get('event_image')

            if event_image and event_image.filename:
                # Validate image file
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                max_file_size = 5 * 1024 * 1024  # 5MB limit

                # Check file size
                event_image.seek(0, 2)  # Seek to end
                file_size = event_image.tell()
                event_image.seek(0)  # Reset to beginning

                if file_size > max_file_size:
                    flash('Image file too large. Maximum size is 5MB.', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

                if '.' in event_image.filename:
                    file_ext = event_image.filename.rsplit('.', 1)[1].lower()
                    if file_ext in allowed_extensions:
                        # Create uploads directory if it doesn't exist
                        upload_folder = os.path.join(app.static_folder or 'static', 'uploads')
                        os.makedirs(upload_folder, exist_ok=True)

                        # Generate unique filename with secure filename
                        from werkzeug.utils import secure_filename
                        secure_name = secure_filename(event_image.filename)
                        image_filename = f"event_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secure_name}"
                        image_path = os.path.join(upload_folder, image_filename)
                        event_image.save(image_path)

                        app.logger.info(f'Event image saved: {image_filename}')
                    else:
                        flash('Invalid image format. Please upload PNG, JPG, JPEG, or GIF files.', 'danger')
                        app_logo = AppSetting.get_setting('app_logo')
                        return render_template('create_event.html', 
                                             app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                             categories=categories, event_types=event_types, 
                                             governorates=egyptian_governorates, edit_mode=False)
                else:
                    flash('Invalid image filename. Please include a file extension.', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

            # Create new event using SQLAlchemy ORM instead of raw SQL
            # Set initial status based on user role
            initial_status = 'active' if current_user.can_approve_events() else 'pending'

            new_event = Event(
                name=title,
                description=description,
                event_type_id=int(event_type_id) if event_type_id else None,
                is_online=is_online,
                start_datetime=start_datetime,
                end_datetime=end_datetime,
                registration_deadline=registration_deadline,
                venue_id=None,  # We'll implement venue handling later
                image_file=image_filename,  # Add image filename to event
                governorate=governorate,
                user_id=current_user.id,
                status=initial_status
            )

            db.session.add(new_event)
            db.session.flush()  # Flush to get the ID
            event_id = new_event.id

            # Handle category association if selected using SQLAlchemy ORM
            if category_id:
                try:
                    category = EventCategory.query.get(int(category_id))
                    if category:
                        new_event.categories.append(category)
                except Exception as e:
                    app.logger.error(f'Error associating category: {str(e)}')

            db.session.commit()
            
            # Invalidate caches after successful event creation
            invalidate_dashboard_caches()

            if current_user.can_approve_events():
                success_message = f'Event "{title}" created successfully and is now active!'
            else:
                success_message = f'Event "{title}" created successfully and is pending approval from an admin or event manager.'

            if attendees_count > 0:
                success_message += f' Attendees file uploaded with {attendees_count} participants.'

            app.logger.info(f'Event "{title}" created successfully with ID {event_id} by user {current_user.email}')
            flash(success_message, 'success')
            return redirect(url_for('events'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating event: {str(e)}')
            import traceback
            app.logger.error(f'Full traceback: {traceback.format_exc()}')
            flash(f'Error creating event: {str(e)}. Please check all required fields.', 'danger')

    # Use the global egyptian_governorates list

    app_logo = AppSetting.get_setting('app_logo')
    return render_template('create_event.html', 
                         app_name=app_name,
                         app_logo=app_logo,
                         theme_color=theme_color,
                         categories=categories,
                         event_types=event_types,
                         governorates=egyptian_governorates,
                         edit_mode=False)

@app.route('/settings')
@login_required
def settings():
    # Get app settings from database
    app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
    theme_color = AppSetting.get_setting('theme_color', '#0f6e84')

    # Get categories from database using ORM
    try:
        categories = [{'id': cat.id, 'name': cat.name} for cat in EventCategory.query.order_by(EventCategory.name).all()]
    except Exception as e:
        app.logger.error(f'Error fetching categories: {str(e)}')
        categories = []

    # Get event types from database using ORM
    try:
        event_types = [{'id': et.id, 'name': et.name} for et in EventType.query.order_by(EventType.name).all()]
    except Exception as e:
        app.logger.error(f'Error fetching event types: {str(e)}')
        event_types = []

    # Get actual users from database
    users = [{'id': u.id, 'email': u.email, 'role': u.role} for u in User.query.all()]

    app_logo = AppSetting.get_setting('app_logo')
    main_tagline = AppSetting.get_setting('main_tagline')
    main_header = AppSetting.get_setting('main_header')
    app_description = AppSetting.get_setting('app_description')
    feature1_title = AppSetting.get_setting('feature1_title')
    feature1_description = AppSetting.get_setting('feature1_description')
    feature2_title = AppSetting.get_setting('feature2_title')
    feature2_description = AppSetting.get_setting('feature2_description')
    return render_template('settings.html',
                         app_name=app_name,
                         app_logo=app_logo,
                         theme_color=theme_color,
                         main_tagline=main_tagline,
                         main_header=main_header,
                         app_description=app_description,
                         feature1_title=feature1_title,
                         feature1_description=feature1_description,
                         feature2_title=feature2_title,
                         feature2_description=feature2_description,
                         categories=categories,
                         event_types=event_types,
                         users=users)

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    """Edit an existing event"""
    event = Event.query.get_or_404(event_id)

    # Check if user has permission to edit this event
    if not current_user.is_admin() and event.user_id != current_user.id:
        flash('You do not have permission to edit this event.', 'danger')
        return redirect(url_for('events'))

    if request.method == 'POST':
        # Handle form submission for event updates
        try:
            # Get form data
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            event_type_id = request.form.get('event_type')
            category_id = request.form.get('categories')
            is_online = 'is_online' in request.form
            start_date = request.form.get('start_date')
            start_time = request.form.get('start_time')
            end_date = request.form.get('end_date')
            end_time = request.form.get('end_time')
            governorate = request.form.get('governorate')
            registration_deadline_date = request.form.get('registration_deadline') # Added for editing

            # Update event fields
            if title:
                event.name = title
            if description:
                event.description = description
            if event_type_id:
                event.event_type_id = int(event_type_id)
            event.is_online = is_online
            if governorate:
                event.governorate = governorate

            # Update datetime fields with validation
            try:
                if start_date:
                    if start_time:
                        new_start = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
                    else:
                        new_start = datetime.strptime(start_date, "%Y-%m-%d")
                    event.start_datetime = new_start

                if end_date:
                    if end_time:
                        new_end = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M")
                    else:
                        new_end = datetime.strptime(end_date, "%Y-%m-%d")
                    event.end_datetime = new_end

                # Update registration deadline (required field)
                if registration_deadline_date:
                    new_deadline = datetime.strptime(registration_deadline_date, "%Y-%m-%d")
                    event.registration_deadline = new_deadline
                elif event.start_datetime:
                    # Fallback to start date if not provided
                    event.registration_deadline = event.start_datetime

                # Validate datetime logic
                if event.start_datetime and event.end_datetime and event.end_datetime <= event.start_datetime:
                    flash('End date must be after start date', 'danger')
                    return redirect(url_for('edit_event', event_id=event.id))

                if event.registration_deadline and event.start_datetime and event.registration_deadline > event.start_datetime:
                    flash('Registration deadline must be before or on the event start date', 'danger')
                    return redirect(url_for('edit_event', event_id=event.id))

            except ValueError as e:
                flash(f'Invalid date/time format: {str(e)}', 'danger')
                return redirect(url_for('edit_event', event_id=event.id))


            # Handle image upload
            event_image = request.files.get('event_image')
            if event_image and event_image.filename:
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                if '.' in event_image.filename:
                    file_ext = event_image.filename.rsplit('.', 1)[1].lower()
                    if file_ext in allowed_extensions:
                        upload_folder = os.path.join(app.static_folder or 'static', 'uploads')
                        os.makedirs(upload_folder, exist_ok=True)

                        image_filename = f"event_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"
                        image_path = os.path.join(upload_folder, image_filename)
                        event_image.save(image_path)

                        event.image_file = image_filename
                        app.logger.info(f'Event image updated: {image_filename}')

            # Update category association
            if category_id:
                # Clear existing categories
                event.categories.clear()
                # Add new category
                category = EventCategory.query.get(int(category_id))
                if category:
                    event.categories.append(category)

            db.session.commit()
            
            # Invalidate caches after successful event update
            invalidate_dashboard_caches()
            
            flash(f'Event "{event.name}" updated successfully!', 'success')
            return redirect(url_for('events'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating event: {str(e)}')
            flash('Error updating event. Please try again.', 'danger')

    # Get app settings
    app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
    theme_color = AppSetting.get_setting('theme_color', '#0f6e84')

    # Get categories and event types from database using ORM
    try:
        categories = [{'id': cat.id, 'name': cat.name} for cat in EventCategory.query.order_by(EventCategory.name).all()]
    except Exception as e:
        app.logger.error(f'Error fetching categories: {str(e)}')
        categories = []

    try:
        event_types = [{'id': et.id, 'name': et.name} for et in EventType.query.order_by(EventType.name).all()]
    except Exception as e:
        app.logger.error(f'Error fetching event types: {str(e)}')
        event_types = []

    return render_template('create_event.html', 
                         app_name=app_name,
                         app_logo=None,
                         theme_color=theme_color,
                         categories=categories,
                         event_types=event_types,
                         governorates=egyptian_governorates,
                         edit_mode=True,
                         event=event)

@app.route('/approve_event/<int:event_id>', methods=['POST'])
@login_required
def approve_event(event_id):
    """Approve an event (admin and event manager only)"""
    if not current_user.can_approve_events():
        flash('Access denied. Admin or Event Manager privileges required.', 'danger')
        return redirect(url_for('events'))

    try:
        event = Event.query.get_or_404(event_id)
        event.status = 'active'
        db.session.commit()
        
        # Invalidate caches after status change
        invalidate_dashboard_caches()
        
        flash(f'Event "{event.name}" has been approved.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error approving event {event_id}: {str(e)}')
        flash('Error approving event. Please try again.', 'danger')

    return redirect(url_for('events'))

@app.route('/reject_event/<int:event_id>', methods=['POST'])
@login_required
def reject_event(event_id):
    """Reject an event (admin and event manager only)"""
    if not current_user.can_approve_events():
        flash('Access denied. Admin or Event Manager privileges required.', 'danger')
        return redirect(url_for('events'))

    try:
        event = Event.query.get_or_404(event_id)
        event.status = 'declined'
        db.session.commit()
        
        # Invalidate caches after status change
        invalidate_dashboard_caches()
        
        flash(f'Event "{event.name}" has been declined.', 'warning')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error declining event {event_id}: {str(e)}')
        flash('Error declining event. Please try again.', 'danger')

    return redirect(url_for('events'))

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    """Delete an event (admin only)"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('events'))

    try:
        event = Event.query.get_or_404(event_id)
        event_name = event.name
        db.session.delete(event)
        db.session.commit()
        
        # Invalidate caches after event deletion
        invalidate_dashboard_caches()
        
        flash(f'Event "{event_name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting event: {str(e)}')
        flash('Error deleting event. Please try again.', 'danger')

    return redirect(url_for('events'))

@app.route('/export_events')
@login_required
@limiter.limit("5 per hour")  # Limit exports due to resource intensity
def export_events():
    """Export events to CSV file with optimized streaming"""
    
    # Capture user permissions and fetch all events data in the request context
    can_approve = current_user.can_approve_events()
    user_id = current_user.id
    user_email = current_user.email
    
    # Fetch all events data and convert to plain dictionaries within the request context
    if can_approve:
        events_query = Event.query.options(
            db.joinedload(Event.event_type),
            db.joinedload(Event.creator),
            db.joinedload(Event.categories)
        ).order_by(Event.created_at.desc()).all()
    else:
        events_query = Event.query.options(
            db.joinedload(Event.event_type),
            db.joinedload(Event.creator),
            db.joinedload(Event.categories)
        ).filter_by(user_id=user_id).order_by(Event.created_at.desc()).all()
    
    # Convert to plain dictionaries to avoid session issues
    events_data = []
    for event in events_query:
        event_dict = {
            'id': event.id,
            'name': event.name,
            'description': event.description or '',
            'event_type': event.event_type.name if event.event_type else 'Not specified',
            'is_online': event.is_online,
            'start_datetime': event.start_datetime.strftime('%Y-%m-%d %H:%M') if event.start_datetime else '',
            'end_datetime': event.end_datetime.strftime('%Y-%m-%d %H:%M') if event.end_datetime else '',
            'governorate': event.governorate or '',
            'categories': ', '.join([category.name for category in event.categories]) if event.categories else 'None',
            'creator_email': event.creator.email if event.creator else '',
            'created_at': event.created_at.strftime('%Y-%m-%d %H:%M') if event.created_at else '',
            'status': event.status or 'Active'
        }
        events_data.append(event_dict)
    
    def generate_csv(events_list):
        """Generator function for streaming CSV export"""
        output = io.StringIO()
        fieldnames = [
            'ID', 'Event Name', 'Description', 'Event Type', 'Is Online', 
            'Start Date', 'End Date', 'Governorate', 'Categories', 
            'Created By', 'Created At', 'Status'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        
        # Process events in batches
        batch_size = 50
        total_events = len(events_list)
        
        for i in range(0, total_events, batch_size):
            batch = events_list[i:i + batch_size]
            
            for event_data in batch:
                writer.writerow({
                    'ID': event_data['id'],
                    'Event Name': event_data['name'],
                    'Description': event_data['description'],
                    'Event Type': event_data['event_type'],
                    'Is Online': 'Yes' if event_data['is_online'] else 'No',
                    'Start Date': event_data['start_datetime'],
                    'End Date': event_data['end_datetime'],
                    'Governorate': event_data['governorate'],
                    'Categories': event_data['categories'],
                    'Created By': event_data['creator_email'],
                    'Created At': event_data['created_at'],
                    'Status': event_data['status']
                })
                
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
    
    try:
        # Create streaming response
        response = make_response(generate_csv(events_data))
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=events_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        app.logger.info(f'Events export started by user {user_email}')
        return response
        
    except Exception as e:
        app.logger.error(f'Error exporting events: {str(e)}')
        flash('Error exporting events. Please try again.', 'danger')
        return redirect(url_for('events'))

@app.route('/api/download/attendees-template')
@login_required
def download_attendees_template():
    """Download CSV template for attendees upload"""

    # Create CSV template content
    csv_content = io.StringIO()
    csv_writer = csv.writer(csv_content)

    # Write header row
    csv_writer.writerow(['Name', 'Email', 'Phone', 'Title', 'Company', 'Department', 'Special_Requirements'])

    # Write sample rows
    csv_writer.writerow(['Dr. Ahmed Hassan', 'ahmed.hassan@example.com', '+20 123 456 7890', 'Cardiologist', 'Cairo Medical Center', 'Cardiology', 'Vegetarian meal'])
    csv_writer.writerow(['Dr. Sarah Mohamed', 'sarah.mohamed@example.com', '+20 987 654 3210', 'Neurologist', 'Alexandria Hospital', 'Neurology', ''])

    # Create response
    response = make_response(csv_content.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=attendees_template.csv'

    return response

@app.route('/api/download/users-template')
@login_required
def download_users_template():
    """Download Excel template for bulk user creation"""

    # Create sample data for the template - Required columns first
    sample_data = {
        'Email': ['ahmed.hassan@example.com', 'sarah.mohamed@example.com', 'mohamed.ali@example.com'],
        'Role': ['medical_rep', 'event_manager', 'admin'],
        'Password': ['SecurePass123!', 'MyPassword456#', 'AdminPass789$'],
        'Full Name': ['Dr. Ahmed Hassan', 'Dr. Sarah Mohamed', 'Dr. Mohamed Ali'],  # Optional field
        'Department': ['Cardiology', 'Neurology', 'Administration'],
        'Phone': ['+20 123 456 7890', '+20 987 654 3210', '+20 555 123 4567'],
        'Employee ID': ['EMP001', 'EMP002', 'EMP003']
    }

    df = pd.DataFrame(sample_data)

    # Create Excel file in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Users')
    output.seek(0)

    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = 'attachment; filename=users_template.xlsx'

    return response

@app.route('/bulk-user-upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("3 per hour")  # Very restrictive for bulk operations
def bulk_user_upload():
    """Handle bulk user creation from Excel file"""
    app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
    theme_color = AppSetting.get_setting('theme_color', '#0f6e84')

    if request.method == 'POST':
        users_file = request.files.get('users_file')

        if not users_file or not users_file.filename:
            flash('Please select a file to upload', 'danger')
            return render_template('bulk_user_upload.html', 
                                 app_name=app_name, theme_color=theme_color)

        # Validate file extension
        allowed_extensions = {'xlsx', 'xls'}
        file_ext = users_file.filename.rsplit('.', 1)[1].lower() if '.' in users_file.filename else ''

        if file_ext not in allowed_extensions:
            flash('Please upload an Excel file (.xlsx or .xls)', 'danger')
            return render_template('bulk_user_upload.html', 
                                 app_name=app_name, theme_color=theme_color)

        try:
            # Read Excel file
            df = pd.read_excel(users_file)

            # Flexible column matching based on actual Excel file structure
            df_columns = df.columns.tolist()
            app.logger.info(f'Excel columns found: {df_columns}')

            # Map the actual columns from the Excel file
            email_col = None
            password_col = None  
            role_col = None

            for col in df_columns:
                col_lower = col.lower().strip()
                if 'email' in col_lower:
                    email_col = col
                elif 'password' in col_lower:
                    password_col = col
                elif 'role' in col_lower:
                    role_col = col

            # Check if we have the required columns
            missing_columns = []
            if not email_col:
                missing_columns.append('Email')
            if not password_col:
                missing_columns.append('Password')
            if not role_col:
                missing_columns.append('Role')

            if missing_columns:
                flash(f'Missing required columns: {", ".join(missing_columns)}. Please download the template and use the correct format.', 'danger')
                return render_template('bulk_user_upload.html', 
                                     app_name=app_name, theme_color=theme_color)

            # Process users in batches for better performance
            success_count = 0
            error_count = 0
            errors = []
            batch_size = 50  # Process in batches of 50 users

            # Pre-validate all data first
            users_to_create = []
            existing_emails = set()

            # Get all existing emails in one query for efficiency
            existing_users = db.session.query(User.email).all()
            existing_emails = {email[0].lower() for email in existing_users}

            # Validate all rows first
            for index, row in df.iterrows():
                try:
                    row_num = int(index) if isinstance(index, (int, float)) else 0
                    email = str(row[email_col]).strip().lower() if email_col and pd.notna(row[email_col]) else ''
                    role = str(row[role_col]).strip().lower() if role_col and pd.notna(row[role_col]) else ''
                    user_password = str(row[password_col]).strip() if password_col and pd.notna(row[password_col]) else None

                    # Validate required fields
                    if not email or not role or not user_password:
                        errors.append(f'Row {row_num + 2}: Missing required fields (Email, Password, or Role)')
                        error_count += 1
                        continue

                    # Normalize role names
                    role_mapping = {
                        'medical rep': 'medical_rep',
                        'medical_rep': 'medical_rep', 
                        'event manager': 'event_manager',
                        'event_manager': 'event_manager',
                        'admin': 'admin'
                    }

                    normalized_role = role_mapping.get(role, role)
                    valid_roles = ['admin', 'event_manager', 'medical_rep']

                    if normalized_role not in valid_roles:
                        errors.append(f'Row {row_num + 2}: Invalid role "{role}". Must be one of: admin, event_manager, medical_rep')
                        error_count += 1
                        continue

                    # Check if user already exists
                    if email in existing_emails:
                        errors.append(f'Row {row_num + 2}: User with email "{email}" already exists')
                        error_count += 1
                        continue

                    # Add to existing emails to catch duplicates within the file
                    if email in [u['email'] for u in users_to_create]:
                        errors.append(f'Row {row_num + 2}: Duplicate email "{email}" in file')
                        error_count += 1
                        continue

                    users_to_create.append({
                        'email': email,
                        'role': normalized_role,
                        'password': user_password
                    })

                except Exception as e:
                    row_num = int(index) if isinstance(index, (int, float)) else 0
                    errors.append(f'Row {row_num + 2}: {str(e)}')
                    error_count += 1

            # Create users in batches
            try:
                for i in range(0, len(users_to_create), batch_size):
                    batch = users_to_create[i:i + batch_size]
                    batch_success_count = 0

                    try:
                        for user_data in batch:
                            new_user = User()
                            new_user.email = user_data['email']
                            new_user.role = user_data['role']
                            new_user.set_password(user_data['password'])
                            db.session.add(new_user)
                            batch_success_count += 1

                        # Commit each batch
                        db.session.commit()
                        success_count += batch_success_count
                        app.logger.info(f'Processed batch {i//batch_size + 1}, created {len(batch)} users')
                        
                    except Exception as batch_error:
                        db.session.rollback()
                        app.logger.error(f'Error in batch {i//batch_size + 1}: {str(batch_error)}')
                        errors.append(f'Batch {i//batch_size + 1}: Database error - {str(batch_error)}')
                        error_count += len(batch)

                # Flash success/error messages
                if success_count > 0:
                    flash(f'Successfully created {success_count} users!', 'success')

                if error_count > 0:
                    flash(f'Failed to create {error_count} users. See details below.', 'warning')
                    for error in errors[:10]:  # Show first 10 errors
                        flash(error, 'danger')
                    if len(errors) > 10:
                        flash(f'... and {len(errors) - 10} more errors', 'danger')

            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error committing bulk user creation: {str(e)}')
                flash(f'Database error: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error processing bulk user upload: {str(e)}')
            flash(f'Error processing file: {str(e)}', 'danger')

    return render_template('bulk_user_upload.html', 
                         app_name=app_name, theme_color=theme_color)

def get_filtered_dashboard_stats(user_id, is_admin, search_query='', category_filter='all', type_filter='all', date_filter='all'):
    """Get dashboard statistics with filters applied"""
    from sqlalchemy import func
    
    now = datetime.now()
    
    # Build base query
    if is_admin:
        query = Event.query
    else:
        query = Event.query.filter_by(user_id=user_id)
    
    # Apply search filter
    if search_query:
        query = query.filter(
            db.or_(
                Event.name.ilike(f'%{search_query}%'),
                Event.description.ilike(f'%{search_query}%'),
                Event.location.ilike(f'%{search_query}%')
            )
        )
    
    # Apply category filter
    if category_filter != 'all':
        try:
            category_id = int(category_filter)
            query = query.filter(Event.categories.any(EventCategory.id == category_id))
        except (ValueError, TypeError):
            pass
    
    # Apply event type filter
    if type_filter != 'all':
        try:
            type_id = int(type_filter)
            query = query.filter_by(event_type_id=type_id)
        except (ValueError, TypeError):
            pass
    
    # Apply date filter
    if date_filter == 'upcoming':
        query = query.filter(Event.start_datetime > now)
    elif date_filter == 'past':
        query = query.filter(Event.start_datetime < now)
    elif date_filter == 'this_month':
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        query = query.filter(Event.start_datetime >= start_of_month, Event.start_datetime <= end_of_month)
    elif date_filter == 'last_month':
        first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        first_of_last_month = (first_of_this_month - timedelta(days=1)).replace(day=1)
        last_of_last_month = first_of_this_month - timedelta(seconds=1)
        query = query.filter(Event.start_datetime >= first_of_last_month, Event.start_datetime <= last_of_last_month)
    
    # Calculate statistics
    total_events = query.count()
    upcoming_events = query.filter(Event.start_datetime > now).count()
    online_events = query.filter_by(is_online=True).count()
    offline_events = query.filter_by(is_online=False).count()
    pending_events = query.filter_by(status='pending').count() if is_admin else 0
    
    return {
        'total_events': total_events,
        'upcoming_events': upcoming_events,
        'online_events': online_events,
        'offline_events': offline_events,
        'pending_events': pending_events
    }

def get_filtered_category_data(user_id, is_admin, search_query='', category_filter='all', type_filter='all', date_filter='all'):
    """Get filtered category data for charts"""
    from sqlalchemy import func
    
    # Build base query
    if is_admin:
        query = db.session.query(EventCategory.name, func.count(Event.id).label('count')).join(
            event_categories, EventCategory.id == event_categories.c.category_id
        ).join(Event, Event.id == event_categories.c.event_id)
    else:
        query = db.session.query(EventCategory.name, func.count(Event.id).label('count')).join(
            event_categories, EventCategory.id == event_categories.c.category_id
        ).join(Event, Event.id == event_categories.c.event_id).filter(Event.user_id == user_id)
    
    # Apply filters (similar logic as dashboard stats)
    query = apply_chart_filters(query, search_query, category_filter, type_filter, date_filter)
    
    results = query.group_by(EventCategory.id, EventCategory.name).all()
    return [{'name': name, 'count': count} for name, count in results]

def get_filtered_type_data(user_id, is_admin, search_query='', category_filter='all', type_filter='all', date_filter='all'):
    """Get filtered event type data for charts"""
    from sqlalchemy import func
    
    # Build base query
    if is_admin:
        query = db.session.query(EventType.name, func.count(Event.id).label('count')).join(
            Event, Event.event_type_id == EventType.id
        )
    else:
        query = db.session.query(EventType.name, func.count(Event.id).label('count')).join(
            Event, Event.event_type_id == EventType.id
        ).filter(Event.user_id == user_id)
    
    # Apply filters
    query = apply_chart_filters(query, search_query, category_filter, type_filter, date_filter)
    
    results = query.group_by(EventType.id, EventType.name).all()
    return [{'name': name, 'count': count} for name, count in results]

def get_filtered_monthly_data(user_id, is_admin, search_query='', category_filter='all', type_filter='all', date_filter='all'):
    """Get filtered monthly data for charts"""
    from sqlalchemy import func, extract
    current_year = datetime.now().year
    
    # Build base query
    if is_admin:
        query = db.session.query(
            extract('month', Event.start_datetime).label('month'),
            func.count(Event.id).label('count')
        ).filter(extract('year', Event.start_datetime) == current_year)
    else:
        query = db.session.query(
            extract('month', Event.start_datetime).label('month'),
            func.count(Event.id).label('count')
        ).filter(
            Event.user_id == user_id,
            extract('year', Event.start_datetime) == current_year
        )
    
    # Apply filters
    query = apply_chart_filters(query, search_query, category_filter, type_filter, date_filter)
    
    results = query.group_by(extract('month', Event.start_datetime)).all()
    
    # Initialize all months with 0
    monthly_counts = [0] * 12
    for month, count in results:
        if month:
            monthly_counts[int(month) - 1] = count
    
    return {
        'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        'data': monthly_counts
    }

def get_filtered_requester_data(user_id, is_admin, search_query='', category_filter='all', type_filter='all', date_filter='all'):
    """Get filtered requester data for charts"""
    from sqlalchemy import func
    
    # Build base query
    if is_admin:
        query = db.session.query(
            User.email,
            func.count(Event.id).label('event_count')
        ).join(Event, User.id == Event.user_id)
    else:
        # For regular users, only show their own data
        query = db.session.query(
            User.email,
            func.count(Event.id).label('event_count')
        ).join(Event, User.id == Event.user_id).filter(Event.user_id == user_id)
    
    # Apply filters
    query = apply_chart_filters(query, search_query, category_filter, type_filter, date_filter)
    
    results = query.group_by(User.id, User.email).all()
    return [{'name': email, 'count': count} for email, count in results]

def apply_chart_filters(query, search_query='', category_filter='all', type_filter='all', date_filter='all'):
    """Apply common filters to chart queries"""
    now = datetime.now()
    
    # Apply search filter
    if search_query:
        query = query.filter(
            db.or_(
                Event.name.ilike(f'%{search_query}%'),
                Event.description.ilike(f'%{search_query}%'),
                Event.location.ilike(f'%{search_query}%')
            )
        )
    
    # Apply category filter
    if category_filter != 'all':
        try:
            category_id = int(category_filter)
            query = query.filter(Event.categories.any(EventCategory.id == category_id))
        except (ValueError, TypeError):
            pass
    
    # Apply event type filter
    if type_filter != 'all':
        try:
            type_id = int(type_filter)
            query = query.filter(Event.event_type_id == type_id)
        except (ValueError, TypeError):
            pass
    
    # Apply date filter
    if date_filter == 'upcoming':
        query = query.filter(Event.start_datetime > now)
    elif date_filter == 'past':
        query = query.filter(Event.start_datetime < now)
    elif date_filter == 'this_month':
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        query = query.filter(Event.start_datetime >= start_of_month, Event.start_datetime <= end_of_month)
    elif date_filter == 'last_month':
        first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        first_of_last_month = (first_of_this_month - timedelta(days=1)).replace(day=1)
        last_of_last_month = first_of_this_month - timedelta(seconds=1)
        query = query.filter(Event.start_datetime >= first_of_last_month, Event.start_datetime <= last_of_last_month)
    
    return query

@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    from flask import jsonify
    
    try:
        # Use cached stats for better performance
        stats = get_dashboard_stats_cached(
            user_id=current_user.id,
            is_admin=current_user.can_approve_events()
        )
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f'Error getting dashboard stats: {str(e)}')
        return jsonify({
            'total_events': 0,
            'upcoming_events': 0,
            'online_events': 0,
            'offline_events': 0,
            'pending_events': 0,
            'completed_events': 0
        })

@app.route('/api/dashboard/categories')
@login_required
def api_category_data():
    from flask import jsonify
    try:
        # Get filter parameters from URL
        search_query = request.args.get('search', '').strip()
        category_filter = request.args.get('category', 'all')
        type_filter = request.args.get('type', 'all')
        date_filter = request.args.get('date', 'all')
        
        # Use filtered data instead of cached data
        categories_data = get_filtered_category_data(
            user_id=current_user.id,
            is_admin=current_user.can_approve_events(),
            search_query=search_query,
            category_filter=category_filter,
            type_filter=type_filter,
            date_filter=date_filter
        )
        return jsonify(categories_data)
    except Exception as e:
        app.logger.error(f'Error getting category data: {str(e)}')
        return jsonify([])

@app.route('/api/dashboard/monthly')
@login_required  
def api_monthly_data():
    from flask import jsonify
    
    try:
        # Get filter parameters from URL
        search_query = request.args.get('search', '').strip()
        category_filter = request.args.get('category', 'all')
        type_filter = request.args.get('type', 'all')
        date_filter = request.args.get('date', 'all')
        
        # Use filtered monthly data
        monthly_data = get_filtered_monthly_data(
            user_id=current_user.id,
            is_admin=current_user.can_approve_events(),
            search_query=search_query,
            category_filter=category_filter,
            type_filter=type_filter,
            date_filter=date_filter
        )
        return jsonify(monthly_data)
    except Exception as e:
        app.logger.error(f'Error getting monthly data: {str(e)}')
        return jsonify({
            'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            'data': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        })

@cache.memoize(timeout=600)  # Cache for 10 minutes
def get_event_types_data_cached(user_id, is_admin):
    """Get cached event types distribution"""
    from sqlalchemy import func
    
    if is_admin:
        result = db.session.query(
            EventType.name,
            func.count(Event.id).label('count')
        ).outerjoin(Event, EventType.id == Event.event_type_id).group_by(
            EventType.id, EventType.name
        ).having(func.count(Event.id) > 0).order_by(func.count(Event.id).desc()).all()
    else:
        result = db.session.query(
            EventType.name,
            func.count(Event.id).label('count')
        ).outerjoin(Event, EventType.id == Event.event_type_id).filter(
            Event.user_id == user_id
        ).group_by(
            EventType.id, EventType.name
        ).having(func.count(Event.id) > 0).order_by(func.count(Event.id).desc()).all()
    
    event_types_data = [{'name': row[0], 'count': row[1]} for row in result]
    
    # If no events, show online vs offline distribution
    if not event_types_data:
        if is_admin:
            online_count = Event.query.filter_by(is_online=True).count()
            offline_count = Event.query.filter_by(is_online=False).count()
        else:
            online_count = Event.query.filter_by(user_id=user_id, is_online=True).count()
            offline_count = Event.query.filter_by(user_id=user_id, is_online=False).count()
            
        if online_count > 0 or offline_count > 0:
            event_types_data = [
                {'name': 'Online Events', 'count': online_count},
                {'name': 'Offline Events', 'count': offline_count}
            ]
    
    return event_types_data

@app.route('/api/dashboard/event-types')
@login_required
def api_event_types_data():
    from flask import jsonify
    try:
        # Get filter parameters from URL
        search_query = request.args.get('search', '').strip()
        category_filter = request.args.get('category', 'all')
        type_filter = request.args.get('type', 'all')
        date_filter = request.args.get('date', 'all')
        
        # Use filtered data instead of cached data
        event_types_data = get_filtered_type_data(
            user_id=current_user.id,
            is_admin=current_user.can_approve_events(),
            search_query=search_query,
            category_filter=category_filter,
            type_filter=type_filter,
            date_filter=date_filter
        )
        return jsonify(event_types_data)
    except Exception as e:
        app.logger.error(f'Error getting event types data: {str(e)}')
        return jsonify([])

# Cache invalidation helper functions
def invalidate_dashboard_caches():
    """Invalidate all dashboard-related caches when data changes"""
    try:
        cache.delete_memoized(get_dashboard_stats_cached)
        cache.delete_memoized(get_category_data_cached)
        cache.delete_memoized(get_monthly_data_cached)
        cache.delete_memoized(get_event_types_data_cached)
        cache.delete_memoized(get_requester_data_cached)
        app.logger.info('Dashboard caches invalidated')
    except Exception as e:
        app.logger.error(f'Error invalidating caches: {str(e)}')

def create_database_indexes():
    """Create additional database indexes for performance optimization"""
    try:
        # The indexes are already defined in the Event model's __table_args__
        # This function is for future manual index creation if needed
        app.logger.info('Database indexes are defined in model schema')
        
        # Additional indexes can be created here if needed
        # Example: db.session.execute('CREATE INDEX IF NOT EXISTS idx_custom ON table (column)')
        
    except Exception as e:
        app.logger.error(f'Error creating database indexes: {str(e)}')

@cache.memoize(timeout=600)  # Cache for 10 minutes
def get_requester_data_cached(user_id, is_admin):
    """Get cached requester distribution data"""
    from sqlalchemy import func
    
    if is_admin:
        results = db.session.query(
            User.email,
            func.count(Event.id).label('event_count')
        ).join(Event, User.id == Event.user_id).group_by(User.id, User.email).all()
    else:
        results = db.session.query(
            User.email,
            func.count(Event.id).label('event_count')
        ).join(Event, User.id == Event.user_id).filter(User.id == user_id).group_by(User.id, User.email).all()
    
    requester_data = [{'name': email, 'count': count} for email, count in results]
    requester_data.sort(key=lambda x: x['count'], reverse=True)
    
    return requester_data

@app.route('/api/dashboard/requesters')
@login_required
def api_requester_data():
    from flask import jsonify
    try:
        # Get filter parameters from URL
        search_query = request.args.get('search', '').strip()
        category_filter = request.args.get('category', 'all')
        type_filter = request.args.get('type', 'all')
        date_filter = request.args.get('date', 'all')
        
        # Use filtered requester data instead of cached data
        requester_data = get_filtered_requester_data(
            user_id=current_user.id,
            is_admin=current_user.can_approve_events(),
            search_query=search_query,
            category_filter=category_filter,
            type_filter=type_filter,
            date_filter=date_filter
        )
        
        # Sort by count (descending order)
        requester_data.sort(key=lambda x: x['count'], reverse=True)
        
        return jsonify(requester_data)
    except Exception as e:
        app.logger.error(f'Error getting requester data: {str(e)}')
        return jsonify([])



@app.route('/api/settings/theme', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def api_update_theme():
    from flask import jsonify, request
    import re
    try:
        app.logger.info(f'Theme update request: authenticated={current_user.is_authenticated}')

        # Check if user is authenticated
        if not current_user.is_authenticated:
            app.logger.warning('Unauthenticated theme update attempt')
            return jsonify({'error': 'Not authenticated', 'debug': 'User not logged in'}), 401

        data = request.get_json()
        app.logger.info(f'Theme update data: {data}')

        if not data or 'theme_color' not in data:
            return jsonify({'error': 'Theme color is required'}), 400

        theme_color = data['theme_color'].strip()
        
        # Validate hex color format
        if not re.match(r'^#[0-9A-Fa-f]{6}$', theme_color):
            return jsonify({'error': 'Invalid color format. Use hex format like #FF0000'}), 400
            
        # Save to database
        AppSetting.set_setting('theme_color', theme_color)
        app.logger.info(f'Theme color saved: {theme_color}')
        # Don't flash message for API calls - JavaScript handles notifications
        return jsonify({'success': True, 'theme_color': theme_color})
    except Exception as e:
        app.logger.error(f'Error in api_update_theme: {str(e)}')
        return jsonify({'error': str(e), 'debug': 'Server error occurred'}), 500

@app.route('/api/settings/app', methods=['POST'])
@login_required
def api_update_app_settings():
    from flask import jsonify, request
    try:
        # Check if user is authenticated
        if not current_user.is_authenticated:
            return jsonify({'error': 'Not authenticated'}), 401

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Save to database
        if 'name' in data:
            AppSetting.set_setting('app_name', data['name'])
            # Don't flash message for API calls - JavaScript handles notifications
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'Error in api_update_app_settings: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/login-content', methods=['POST'])
@login_required
def api_update_login_content():
    from flask import jsonify, request
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Save each field to database
        if 'main_tagline' in data:
            AppSetting.set_setting('main_tagline', data['main_tagline'])
        if 'main_header' in data:
            AppSetting.set_setting('main_header', data['main_header'])
        if 'app_description' in data:
            AppSetting.set_setting('app_description', data['app_description'])
        if 'feature1_title' in data:
            AppSetting.set_setting('feature1_title', data['feature1_title'])
        if 'feature1_description' in data:
            AppSetting.set_setting('feature1_description', data['feature1_description'])
        if 'feature2_title' in data:
            AppSetting.set_setting('feature2_title', data['feature2_title'])
        if 'feature2_description' in data:
            AppSetting.set_setting('feature2_description', data['feature2_description'])

        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'Error updating login content: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    # Secure file serving route for uploaded files
    from flask import send_from_directory
    from werkzeug.utils import secure_filename
    import os
    
    # Validate filename to prevent directory traversal
    secure_name = secure_filename(filename)
    if secure_name != filename or '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400
    
    # Check if file exists and is in uploads directory
    upload_path = os.path.join(app.static_folder or 'static', 'uploads')
    file_path = os.path.join(upload_path, secure_name)
    
    if not os.path.exists(file_path) or not os.path.commonpath([upload_path, file_path]) == upload_path:
        return "File not found", 404
        
    return send_from_directory('static/uploads', secure_name)

@app.route('/api/settings/logo', methods=['POST'])
@login_required
def api_upload_logo():
    from flask import jsonify, request, make_response
    try:
        if 'logo' not in request.files:
            return jsonify({'error': 'No logo file provided'}), 400

        logo_file = request.files['logo']
        if logo_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'svg'}
        if logo_file.filename and '.' in logo_file.filename:
            file_ext = logo_file.filename.rsplit('.', 1)[1].lower()
        else:
            file_ext = ''

        if file_ext not in allowed_extensions:
            return jsonify({'error': 'Invalid file type. Please upload PNG, JPG, JPEG, or SVG files only.'}), 400

        # Create uploads directory if it doesn't exist
        upload_folder = os.path.join(app.static_folder or 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        # Generate unique filename
        logo_filename = f"logo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"
        logo_path = os.path.join(upload_folder, logo_filename)

        # Save the file
        logo_file.save(logo_path)

        # Store logo path in settings
        logo_url = f"/static/uploads/{logo_filename}"
        AppSetting.set_setting('app_logo', logo_url)

        app.logger.info(f'Logo uploaded successfully: {logo_url}')
        return jsonify({'success': True, 'logo_url': logo_url, 'message': 'Logo uploaded successfully!'})

    except Exception as e:
        app.logger.error(f'Error uploading logo: {str(e)}')
        return jsonify({'error': f'Failed to upload logo: {str(e)}'}), 500

@app.route('/api/settings/logo', methods=['DELETE'])
@login_required
def api_remove_logo():
    from flask import jsonify
    try:
        # Get current logo to remove the file
        current_logo = AppSetting.get_setting('app_logo')
        
        # Remove logo setting from database
        AppSetting.set_setting('app_logo', None)
        
        # Try to remove the physical file if it exists
        if current_logo and current_logo.startswith('/static/uploads/'):
            try:
                file_path = os.path.join(app.static_folder or 'static', 'uploads', 
                                       current_logo.split('/')[-1])
                if os.path.exists(file_path):
                    os.remove(file_path)
                    app.logger.info(f'Removed logo file: {file_path}')
            except Exception as file_error:
                app.logger.warning(f'Could not remove logo file: {str(file_error)}')
        
        app.logger.info('Logo removed successfully')
        return jsonify({'success': True, 'message': 'Logo removed successfully!'})
        
    except Exception as e:
        app.logger.error(f'Error removing logo: {str(e)}')
        return jsonify({'error': f'Failed to remove logo: {str(e)}'}), 500

@app.route('/api/categories', methods=['POST'])
@login_required
def api_add_category():
    from flask import jsonify, request
    try:
        category_name = request.form.get('category_name', '').strip()
        if not category_name:
            return jsonify({'error': 'Category name is required'}), 400

        # Check if category already exists
        existing_category = EventCategory.query.filter_by(name=category_name).first()
        if existing_category:
            return jsonify({'error': 'Category already exists'}), 400

        # Create new category
        new_category = EventCategory(name=category_name)
        db.session.add(new_category)
        db.session.commit()
        
        # Invalidate caches
        invalidate_dashboard_caches()
        
        app.logger.info(f'Category "{category_name}" added by user {current_user.id}')
        return jsonify({'success': True, 'id': new_category.id, 'name': new_category.name})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error adding category: {str(e)}')
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def api_delete_category(category_id):
    from flask import jsonify
    try:
        category = EventCategory.query.get_or_404(category_id)
        
        # Check if category is used by any events
        events_using_category = Event.query.filter(Event.categories.contains(category)).count()
        if events_using_category > 0:
            return jsonify({'error': f'Cannot delete category. It is used by {events_using_category} event(s).'}), 400
        
        category_name = category.name
        db.session.delete(category)
        db.session.commit()
        
        # Invalidate caches
        invalidate_dashboard_caches()
        
        app.logger.info(f'Category "{category_name}" deleted by user {current_user.id}')
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting category {category_id}: {str(e)}')
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/api/event-types', methods=['POST'])
@login_required
def api_add_event_type():
    from flask import jsonify, request
    try:
        type_name = request.form.get('type_name', '').strip()
        if not type_name:
            return jsonify({'error': 'Event type name is required'}), 400

        # Check if event type already exists
        existing_type = EventType.query.filter_by(name=type_name).first()
        if existing_type:
            return jsonify({'error': 'Event type already exists'}), 400

        # Create new event type
        new_event_type = EventType(name=type_name)
        db.session.add(new_event_type)
        db.session.commit()
        
        # Invalidate caches
        invalidate_dashboard_caches()
        
        app.logger.info(f'Event type "{type_name}" added by user {current_user.id}')
        return jsonify({'success': True, 'id': new_event_type.id, 'name': new_event_type.name})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error adding event type: {str(e)}')
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/api/event-types/<int:type_id>', methods=['DELETE'])
@login_required
def api_delete_event_type(type_id):
    from flask import jsonify
    try:
        event_type = EventType.query.get_or_404(type_id)
        
        # Check if event type is used by any events
        events_using_type = Event.query.filter_by(event_type_id=type_id).count()
        if events_using_type > 0:
            return jsonify({'error': f'Cannot delete event type. It is used by {events_using_type} event(s).'}), 400
        
        type_name = event_type.name
        db.session.delete(event_type)
        db.session.commit()
        
        # Invalidate caches
        invalidate_dashboard_caches()
        
        app.logger.info(f'Event type "{type_name}" deleted by user {current_user.id}')
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting event type {type_id}: {str(e)}')
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/api/users', methods=['POST'])
@login_required
def api_add_user():
    from flask import jsonify, request
    try:
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        if not email or not password or not role:
            return jsonify({'error': 'Email, password, and role are required'}), 400

        # Validate role
        valid_roles = ['admin', 'event_manager', 'medical_rep']
        if role not in valid_roles:
            return jsonify({'error': 'Invalid role specified'}), 400

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 400

        # Create new user
        new_user = User()
        new_user.email = email
        new_user.role = role
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        app.logger.info(f'User {email} added successfully with role {role}')
        return jsonify({
            'success': True, 
            'id': new_user.id, 
            'email': new_user.email, 
            'role': new_user.role
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error adding user: {str(e)}')
        return jsonify({'error': f'Failed to add user: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def api_delete_user(user_id):
    from flask import jsonify
    try:
        # Prevent users from deleting themselves
        if user_id == current_user.id:
            return jsonify({'error': 'You cannot delete your own account'}), 400

        user = User.query.get_or_404(user_id)
        user_email = user.email

        # Check if user has created events
        event_count = Event.query.filter_by(user_id=user_id).count()
        if event_count > 0:
            return jsonify({'error': f'Cannot delete user {user_email} - they have {event_count} associated events'}), 400

        db.session.delete(user)
        db.session.commit()

        app.logger.info(f'User {user_email} deleted successfully')
        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting user: {str(e)}')
        return jsonify({'error': f'Failed to delete user: {str(e)}'}), 500

@app.route('/api/users/list', methods=['GET'])
@login_required
def api_list_users():
    from flask import jsonify
    try:
        users = User.query.all()
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'email': user.email,
                'role': user.role
            })

        return jsonify({'success': True, 'users': users_data})

    except Exception as e:
        app.logger.error(f'Error listing users: {str(e)}')
        return jsonify({'error': f'Failed to load users: {str(e)}'}), 500

@app.route('/api/auth/test')
@login_required
def api_auth_test():
    from flask import jsonify
    return jsonify({'authenticated': True, 'user': current_user.email, 'role': current_user.role})

# API Token Management Endpoints
@app.route('/api/tokens', methods=['POST'])
@login_required
@limiter.limit("5 per hour")  # Limit token creation
def api_create_token():
    from flask import jsonify, request
    try:
        data = request.get_json()
        token_name = data.get('name', '').strip()
        
        if not token_name:
            return jsonify({'error': 'Token name is required'}), 400
        
        # Check if user already has 5 or more active tokens
        active_tokens = APIToken.query.filter_by(user_id=current_user.id, is_active=True).count()
        if active_tokens >= 5:
            return jsonify({'error': 'Maximum of 5 active tokens allowed per user'}), 400
        
        token, api_token = APIToken.generate_token(current_user.id, token_name)
        log_security_event("API_TOKEN_CREATED", f"Token '{token_name}' created", user_id=current_user.id)
        
        return jsonify({
            'success': True,
            'token': token,
            'token_id': api_token.id,
            'name': api_token.name,
            'created_at': api_token.created_at.isoformat()
        })
        
    except Exception as e:
        app.logger.error(f'Error creating API token: {str(e)}')
        return jsonify({'error': 'Failed to create token'}), 500

@app.route('/api/tokens', methods=['GET'])
@login_required
def api_list_tokens():
    from flask import jsonify
    try:
        tokens = APIToken.query.filter_by(user_id=current_user.id, is_active=True).all()
        tokens_data = [{
            'id': token.id,
            'name': token.name,
            'created_at': token.created_at.isoformat(),
            'last_used': token.last_used.isoformat() if token.last_used else None
        } for token in tokens]
        
        return jsonify({'tokens': tokens_data})
        
    except Exception as e:
        app.logger.error(f'Error listing API tokens: {str(e)}')
        return jsonify({'error': 'Failed to list tokens'}), 500

@app.route('/api/tokens/<int:token_id>', methods=['DELETE'])
@login_required
def api_delete_token(token_id):
    from flask import jsonify
    try:
        token = APIToken.query.filter_by(id=token_id, user_id=current_user.id).first()
        if not token:
            return jsonify({'error': 'Token not found'}), 404
        
        token.is_active = False
        db.session.commit()
        
        log_security_event("API_TOKEN_REVOKED", f"Token '{token.name}' revoked", user_id=current_user.id)
        return jsonify({'success': True})
        
    except Exception as e:
        app.logger.error(f'Error deleting API token: {str(e)}')
        return jsonify({'error': 'Failed to delete token'}), 500

# Protected API endpoints using token authentication
@app.route('/api/v1/events', methods=['GET'])
@api_token_required
@limiter.limit("100 per hour")
def api_v1_events():
    """API endpoint for getting events with token authentication"""
    from flask import jsonify
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Use optimized pagination function
        events, total_count, has_next, has_prev = get_paginated_events(
            page=page, 
            per_page=per_page,
            user_filter=None if current_user.can_approve_events() else current_user.id
        )
        
        events_data = []
        for event in events:
            events_data.append({
                'id': event.id,
                'name': event.name,
                'description': event.description,
                'start_datetime': event.start_datetime.isoformat() if event.start_datetime else None,
                'end_datetime': event.end_datetime.isoformat() if event.end_datetime else None,
                'is_online': event.is_online,
                'status': event.status,
                'created_at': event.created_at.isoformat() if event.created_at else None
            })
        
        return jsonify({
            'events': events_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'has_next': has_next,
                'has_prev': has_prev
            }
        })
        
    except Exception as e:
        app.logger.error(f'Error in API events endpoint: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/forgot_password')
def forgot_password():
    return '<p>Password reset functionality coming soon. Please contact administrator.</p><p><a href="/login">Back to Login</a></p>'

# Initialize database with connection validation
with app.app_context():
    # Test PostgreSQL connection
    try:
        db.engine.connect()
        print("✓ PostgreSQL database connection successful")
    except Exception as e:
        print(f"✗ PostgreSQL database connection failed: {e}")
        raise RuntimeError(f"Failed to connect to PostgreSQL database: {e}")

    # Create upload directory
    os.makedirs('static/uploads', exist_ok=True)

    # Create all database tables
    db.create_all()

    # Create admin user from environment variables if none exists
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')

    if admin_email and admin_password:
        if not User.query.filter_by(email=admin_email).first():
            admin_user = User()
            admin_user.email = admin_email
            admin_user.role = 'admin'
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info(f'Admin user created from environment: {admin_email}')
    else:
        app.logger.warning('ADMIN_EMAIL and ADMIN_PASSWORD environment variables not set - no default admin user created')

    # Create event categories if they don't exist
    categories = [
        'Cardiology', 'Oncology', 'Neurology', 'Pediatrics', 'Endocrinology',
        'Dermatology', 'Psychiatry', 'Product Launch', 'Medical Education',
        'Patient Awareness', 'Internal Training'
    ]

    for cat_name in categories:
        if not EventCategory.query.filter_by(name=cat_name).first():
            category = EventCategory(name=cat_name)
            db.session.add(category)

    # Create event types if they don't exist
    event_types = [
        'Conference', 'Webinar', 'Workshop', 'Symposium', 
        'Roundtable Meeting', 'Investigator Meeting'
    ]

    for type_name in event_types:
        if not EventType.query.filter_by(name=type_name).first():
            event_type = EventType(name=type_name)
            db.session.add(event_type)

    db.session.commit()

# Database Backup and Restore API Routes
@app.route('/api/database/backup', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def api_database_backup():
    """Create a database backup and download it"""
    from flask import jsonify, make_response
    import subprocess
    import tempfile
    import os
    from datetime import datetime
    
    try:
        # Only admin users can perform database backup
        if current_user.role != 'admin':
            return jsonify({'error': 'Only administrators can create database backups'}), 403
        
        # Get database URL from environment
        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            return jsonify({'error': 'Database URL not configured'}), 500
        
        # Create temporary file for backup
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"database_backup_{timestamp}.sql"
        
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix='.sql') as temp_file:
            try:
                # Use pg_dump to create database backup
                cmd = ['pg_dump', database_url, '--no-owner', '--no-privileges']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    app.logger.error(f'pg_dump failed: {result.stderr}')
                    return jsonify({'error': 'Failed to create database backup'}), 500
                
                # Write backup to temporary file
                temp_file.write(result.stdout.encode('utf-8'))
                temp_file.flush()
                
                # Read the backup content
                temp_file.seek(0)
                backup_content = temp_file.read()
                
                # Create response with file download
                response = make_response(backup_content)
                response.headers['Content-Type'] = 'application/octet-stream'
                response.headers['Content-Disposition'] = f'attachment; filename="{backup_filename}"'
                
                # Log the backup creation
                log_security_event("DATABASE_BACKUP_CREATED", f"Database backup created: {backup_filename}", user_id=current_user.id)
                app.logger.info(f'Database backup created successfully by user {current_user.id}')
                
                return response
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
                    
    except Exception as e:
        app.logger.error(f'Error creating database backup: {str(e)}')
        return jsonify({'error': 'Internal server error occurred during backup'}), 500

@app.route('/api/database/restore', methods=['POST'])
@login_required
@limiter.limit("2 per hour")
def api_database_restore():
    """Restore database from uploaded backup file"""
    from flask import jsonify, request
    import subprocess
    import tempfile
    import os
    
    try:
        # Only admin users can perform database restore
        if current_user.role != 'admin':
            return jsonify({'error': 'Only administrators can restore database backups'}), 403
        
        # Check if backup file was uploaded
        if 'backup_file' not in request.files:
            return jsonify({'error': 'No backup file provided'}), 400
        
        backup_file = request.files['backup_file']
        if backup_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file extension
        if not backup_file.filename.endswith('.sql'):
            return jsonify({'error': 'Invalid file type. Only .sql files are allowed'}), 400
        
        # Get database URL from environment
        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            return jsonify({'error': 'Database URL not configured'}), 500
        
        # Save uploaded file to temporary location
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix='.sql') as temp_file:
            backup_file.save(temp_file.name)
            
            try:
                # Use psql to restore database
                cmd = ['psql', database_url, '-f', temp_file.name]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    app.logger.error(f'Database restore failed: {result.stderr}')
                    return jsonify({'error': 'Failed to restore database backup'}), 500
                
                # Log the restore operation
                log_security_event("DATABASE_RESTORE_COMPLETED", f"Database restored from {backup_file.filename}", user_id=current_user.id)
                app.logger.info(f'Database restored successfully by user {current_user.id} from file {backup_file.filename}')
                
                return jsonify({
                    'success': True, 
                    'message': 'Database restored successfully'
                })
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
                    
    except Exception as e:
        app.logger.error(f'Error restoring database: {str(e)}')
        return jsonify({'error': 'Internal server error occurred during restore'}), 500

    # Log application startup
    log_security_event("APPLICATION_START", "Application started successfully")
    app.logger.info("Database initialization completed with security enhancements")

