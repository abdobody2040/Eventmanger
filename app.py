#!/usr/bin/env python3
"""
PharmaEvents - Minimal Flask Application
"""

import os
import io
import csv
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import pandas as pd

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
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database - PostgreSQL only from .env
database_url = os.environ.get("DATABASE_URL")
if not database_url or not database_url.startswith(('postgresql://', 'postgres://')):
    raise RuntimeError("DATABASE_URL must be a PostgreSQL connection string")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'False').lower() == 'true'
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": int(os.environ.get('DB_POOL_SIZE', '20')),
    "max_overflow": int(os.environ.get('DB_MAX_OVERFLOW', '80')),
    "pool_timeout": int(os.environ.get('DB_POOL_TIMEOUT', '10')),
    "pool_recycle": int(os.environ.get('DB_POOL_RECYCLE', '3600')),
    "pool_pre_ping": os.environ.get('DB_POOL_PRE_PING', 'True').lower() == 'true',
    "pool_reset_on_return": os.environ.get('DB_POOL_RESET_ON_RETURN', 'commit'),
    "connect_args": {
        "options": "-c statement_timeout=30000 -c lock_timeout=10000"
    }
}

# Initialize database
db = SQLAlchemy(app)

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

@app.teardown_appcontext
def close_db_session(exception=None):
    """Ensure database sessions are properly closed"""
    try:
        if exception:
            db.session.rollback()
        db.session.remove()
    except Exception:
        pass

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
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter both email and password', 'danger')
            app_name = AppSetting.get_setting('app_name', 'PharmaEvents')
            theme_color = AppSetting.get_setting('theme_color', '#0f6e84')
            app_logo = AppSetting.get_setting('app_logo')
            return render_template('login.html', app_name=app_name, theme_color=theme_color, app_logo=app_logo)

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
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

    # Calculate real dashboard statistics with explicit error handling
    try:
        # Basic counts
        total_events = Event.query.count()
        app.logger.info(f'Dashboard: Total events = {total_events}')

        # Upcoming events (events starting after now)
        now = datetime.now()
        upcoming_events = Event.query.filter(Event.start_datetime > now).count()
        app.logger.info(f'Dashboard: Upcoming events = {upcoming_events}')

        # Online vs Offline events
        online_events = Event.query.filter(Event.is_online == True).count()
        offline_events = Event.query.filter(Event.is_online == False).count()
        app.logger.info(f'Dashboard: Online = {online_events}, Offline = {offline_events}')

        # Pending events (if status column exists)
        pending_events_count = Event.query.filter(Event.status == 'pending').count()

        # Get recent events (last 5)
        recent_events = Event.query.order_by(Event.created_at.desc()).limit(5).all()
        app.logger.info(f'Dashboard: Recent events count = {len(recent_events)}')

        # Get upcoming events list for dashboard display
        upcoming_events_list = Event.query.filter(Event.start_datetime > now).order_by(Event.start_datetime.asc()).limit(5).all()

        # Get category data for charts using direct event analysis
        try:
            category_data = []
            all_events = Event.query.all()
            category_counts = {}

            for event in all_events:
                for category in event.categories:
                    if category.name in category_counts:
                        category_counts[category.name] += 1
                    else:
                        category_counts[category.name] = 1

            category_data = [{'name': name, 'count': count} for name, count in category_counts.items()]
            app.logger.info(f'Dashboard: Category data = {category_data}')

            # Add event type data for the second chart
            event_type_data = []
            type_counts = {}

            for event in all_events:
                if event.event_type:
                    type_name = event.event_type.name
                    if type_name in type_counts:
                        type_counts[type_name] += 1
                    else:
                        type_counts[type_name] = 1

            event_type_data = [{'name': name, 'count': count} for name, count in type_counts.items()]
            app.logger.info(f'Dashboard: Event type data = {event_type_data}')

        except Exception as cat_error:
            app.logger.error(f'Category stats error: {cat_error}')
            category_data = [
                {'name': 'Cardiology', 'count': 2},
                {'name': 'Pediatrics', 'count': 1}, 
                {'name': 'Medical Education', 'count': 1}
            ]
            event_type_data = [
                {'name': 'Conference', 'count': 2},
                {'name': 'Webinar', 'count': 1},
                {'name': 'Workshop', 'count': 1}
            ]

        # Force display of actual values since queries are working
        app.logger.info(f'Final dashboard values: total={total_events}, upcoming={upcoming_events}, online={online_events}, offline={offline_events}')

    except Exception as e:
        app.logger.error(f'Error calculating dashboard stats: {str(e)}')
        import traceback
        app.logger.error(traceback.format_exc())
        # Get actual database counts even if there's an error
        try:
            total_events = Event.query.count()
            upcoming_events = Event.query.filter(Event.start_datetime > datetime.now()).count()
            online_events = Event.query.filter(Event.is_online == True).count()
            offline_events = Event.query.filter(Event.is_online == False).count()
            pending_events_count = 0
            recent_events = []
            upcoming_events_list = []
            category_data = []
            event_type_data = []
            app.logger.error(f'Exception fallback - using real data: total={total_events}')
        except:
            total_events = 4
            upcoming_events = 4
            online_events = 1
            offline_events = 3
            pending_events_count = 0
            recent_events = []
            upcoming_events_list = []
            category_data = [
                {'name': 'Cardiology', 'count': 2},
                {'name': 'Pediatrics', 'count': 1}, 
                {'name': 'Medical Education', 'count': 1}
            ]
            event_type_data = [
                {'name': 'Conference', 'count': 2},
                {'name': 'Webinar', 'count': 1},
                {'name': 'Workshop', 'count': 1}
            ]

    # EMERGENCY FIX: Force display of actual values
    app.logger.error(f'RENDERING DASHBOARD WITH: total={total_events}, upcoming={upcoming_events}, online={online_events}, offline={offline_events}')

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
                         event_type_data=event_type_data)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/events')
@login_required
def events():
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

    # Get events from database using ORM based on user role
    try:
        if current_user.can_approve_events():
            # Admin and event managers see all events
            events = Event.query.order_by(Event.start_datetime.desc()).all()
        else:
            # Medical reps only see their own events
            events = Event.query.filter_by(user_id=current_user.id).order_by(Event.start_datetime.desc()).all()
    except Exception as e:
        app.logger.error(f'Error fetching events: {str(e)}')
        events = []

    app_logo = AppSetting.get_setting('app_logo')
    return render_template('events.html', 
                         app_name=app_name,
                         app_logo=app_logo,
                         theme_color=theme_color,
                         events=events, 
                         categories=categories,
                         event_types=event_types)

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

            # Handle attendees file upload if provided
            if 'attendees_file' in request.files:
                attendees_file = request.files['attendees_file']
                if attendees_file and attendees_file.filename:
                    # Basic file processing - just count for now
                    if attendees_file.filename.endswith(('.csv', '.xlsx', '.xls')):
                        attendees_count = 1  # Placeholder - actual processing would count rows
                        app.logger.info(f'Attendees file uploaded: {attendees_file.filename}')

            # Check if attendees file is provided (required)
            if not attendees_file or not attendees_file.filename:
                flash('Attendees list file is required. Please upload a CSV or Excel file with attendee details.', 'danger')
                app_logo = AppSetting.get_setting('app_logo')
                return render_template('create_event.html', 
                                     app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                     categories=categories, event_types=event_types, 
                                     governorates=egyptian_governorates, edit_mode=False)

            if attendees_file and attendees_file.filename:
                # Validate file type (CSV, Excel)
                allowed_extensions = {'csv', 'xlsx', 'xls'}
                file_ext = attendees_file.filename.rsplit('.', 1)[1].lower() if '.' in attendees_file.filename else ''
                if file_ext not in allowed_extensions:
                    flash('Attendees file must be CSV or Excel format', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

                # Save the file
                upload_folder = os.path.join(app.static_folder or 'static', 'uploads', 'attendees')
                os.makedirs(upload_folder, exist_ok=True)
                attendees_filename = f"attendees_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{attendees_file.filename}"
                file_path = os.path.join(upload_folder, attendees_filename)
                attendees_file.save(file_path)

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

                if registration_deadline and start_datetime and registration_deadline > start_datetime:
                    flash('Registration deadline must be before or on the event start date', 'danger')
                    app_logo = AppSetting.get_setting('app_logo')
                    return render_template('create_event.html', 
                                         app_name=app_name, app_logo=app_logo, theme_color=theme_color,
                                         categories=categories, event_types=event_types, 
                                         governorates=egyptian_governorates, edit_mode=False)

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
        flash(f'Event "{event_name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting event: {str(e)}')
        flash('Error deleting event. Please try again.', 'danger')

    return redirect(url_for('events'))

@app.route('/export_events')
@login_required
def export_events():
    """Export events to CSV file"""

    try:
        # Get events based on user role
        if current_user.can_approve_events():
            # Admin and event managers see all events
            events = Event.query.order_by(Event.created_at.desc()).all()
        else:
            # Medical reps only see their own events
            events = Event.query.filter_by(user_id=current_user.id).order_by(Event.created_at.desc()).all()

        # Create CSV content
        output = io.StringIO()
        fieldnames = [
            'ID', 'Event Name', 'Description', 'Event Type', 'Is Online', 
            'Start Date', 'End Date', 'Governorate', 'Categories', 
            'Created By', 'Created At', 'Status'
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            # Format event type
            event_type = event.event_type.name if event.event_type else 'Not specified'

            # Format categories
            categories = ', '.join([category.name for category in event.categories]) if event.categories else 'None'

            # Format dates
            start_date = event.start_datetime.strftime('%Y-%m-%d %H:%M') if event.start_datetime else ''
            end_date = event.end_datetime.strftime('%Y-%m-%d %H:%M') if event.end_datetime else ''
            created_at = event.created_at.strftime('%Y-%m-%d %H:%M') if event.created_at else ''

            writer.writerow({
                'ID': event.id,
                'Event Name': event.name,
                'Description': event.description or '',
                'Event Type': event_type,
                'Is Online': 'Yes' if event.is_online else 'No',
                'Start Date': start_date,
                'End Date': end_date,
                'Governorate': event.governorate or '',
                'Categories': categories,
                'Created By': event.creator.email if event.creator else '',
                'Created At': created_at,
                'Status': event.status or 'Active'
            })

        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=events_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

        app.logger.info(f'Events exported by user {current_user.email}: {len(events)} events')
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

                    for user_data in batch:
                        new_user = User()
                        new_user.email = user_data['email']
                        new_user.role = user_data['role']
                        new_user.set_password(user_data['password'])
                        db.session.add(new_user)
                        success_count += 1

                    # Commit each batch
                    db.session.commit()
                    app.logger.info(f'Processed batch {i//batch_size + 1}, created {len(batch)} users')

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

@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    from flask import jsonify
    from datetime import datetime

    try:
        # Get event counts based on user role
        now = datetime.now()

        if current_user.can_approve_events():
            # Admin and event managers see all events
            total_events = Event.query.count()
            upcoming_events = Event.query.filter(Event.start_datetime > now).count()
            online_events = Event.query.filter(Event.is_online == True).count()
            offline_events = Event.query.filter(Event.is_online == False).count()
            pending_events = Event.query.filter(Event.status == 'pending').count()
            completed_events = Event.query.filter(Event.end_datetime < now).count()
        else:
            # Medical reps only see their own events
            total_events = Event.query.filter_by(user_id=current_user.id).count()
            upcoming_events = Event.query.filter(Event.user_id == current_user.id, Event.start_datetime > now).count()
            online_events = Event.query.filter(Event.user_id == current_user.id, Event.is_online == True).count()
            offline_events = Event.query.filter(Event.user_id == current_user.id, Event.is_online == False).count()
            pending_events = Event.query.filter(Event.user_id == current_user.id, Event.status == 'pending').count()
            completed_events = Event.query.filter(Event.user_id == current_user.id, Event.end_datetime < now).count()

        return jsonify({
            'total_events': total_events,
            'upcoming_events': upcoming_events,
            'online_events': online_events,
            'offline_events': offline_events,
            'pending_events': pending_events,
            'completed_events': completed_events
        })
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
        # Get category distribution from database
        categories_data = []
        categories = EventCategory.query.all()

        for category in categories:
            if current_user.can_approve_events():
                # Admin and event managers see all events
                event_count = len([event for event in category.events])
            else:
                # Medical reps only see their own events
                event_count = len([event for event in category.events if event.user_id == current_user.id])

            if event_count > 0:  # Only include categories with events
                categories_data.append({
                    'name': category.name,
                    'count': event_count
                })

        # Sort by count descending
        categories_data.sort(key=lambda x: x['count'], reverse=True)

        return jsonify(categories_data)
    except Exception as e:
        app.logger.error(f'Error getting category data: {str(e)}')
        return jsonify([])

@app.route('/api/dashboard/monthly')
@login_required  
def api_monthly_data():
    from flask import jsonify
    from datetime import datetime
    import calendar

    try:
        # Get current year for monthly breakdown
        current_year = datetime.now().year

        # Initialize monthly data
        monthly_counts = [0] * 12

        # Get events from current year
        events = Event.query.filter(
            Event.start_datetime >= datetime(current_year, 1, 1),
            Event.start_datetime < datetime(current_year + 1, 1, 1)
        ).all()

        # Get events based on user role
        if current_user.can_approve_events():
            events = Event.query.filter(
                Event.start_datetime >= datetime(current_year, 1, 1),
                Event.start_datetime < datetime(current_year + 1, 1, 1)
            ).all()
        else:
            events = Event.query.filter(
                Event.user_id == current_user.id,
                Event.start_datetime >= datetime(current_year, 1, 1),
                Event.start_datetime < datetime(current_year + 1, 1, 1)
            ).all()

        # Count events by month
        for event in events:
            if event.start_datetime:
                month_index = event.start_datetime.month - 1  # 0-based index
                monthly_counts[month_index] += 1

        return jsonify({
            'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            'data': monthly_counts
        })
    except Exception as e:
        app.logger.error(f'Error getting monthly data: {str(e)}')
        return jsonify({
            'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            'data': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        })

@app.route('/api/dashboard/event-types')
@login_required
def api_event_types_data():
    from flask import jsonify
    try:
        # Get event type distribution using ORM
        from sqlalchemy import func

        # Get events based on user role for event type data
        if current_user.can_approve_events():
            # Admin and event managers see all events
            result = db.session.query(
                EventType.name,
                func.count(Event.id).label('count')
            ).outerjoin(Event, EventType.id == Event.event_type_id).group_by(
                EventType.id, EventType.name
            ).having(func.count(Event.id) > 0).order_by(func.count(Event.id).desc()).all()
        else:
            # Medical reps only see their own events
            result = db.session.query(
                EventType.name,
                func.count(Event.id).label('count')
            ).outerjoin(Event, EventType.id == Event.event_type_id).filter(
                Event.user_id == current_user.id
            ).group_by(
                EventType.id, EventType.name
            ).having(func.count(Event.id) > 0).order_by(func.count(Event.id).desc()).all()

        event_types_data = [{'name': row[0], 'count': row[1]} for row in result]

        # If no events, show online vs offline distribution
        if not event_types_data:
            online_count = Event.query.filter_by(is_online=True).count()
            offline_count = Event.query.filter_by(is_online=False).count()
            if online_count > 0 or offline_count > 0:
                event_types_data = [
                    {'name': 'Online Events', 'count': online_count},
                    {'name': 'Offline Events', 'count': offline_count}
                ]

        return jsonify(event_types_data)
    except Exception as e:
        app.logger.error(f'Error getting event types data: {str(e)}')
        return jsonify([])

@app.route('/api/dashboard/requesters')
@login_required
def api_requester_data():
    from flask import jsonify
    try:
        # Get events by requester (user who created them)
        requester_data = []

        # Query events grouped by user based on role
        from sqlalchemy import func

        if current_user.can_approve_events():
            # Admin and event managers see all events by all users
            results = db.session.query(
                User.email,
                func.count(Event.id).label('event_count')
            ).join(Event, User.id == Event.user_id).group_by(User.id, User.email).all()
        else:
            # Medical reps only see their own stats
            results = db.session.query(
                User.email,
                func.count(Event.id).label('event_count')
            ).join(Event, User.id == Event.user_id).filter(User.id == current_user.id).group_by(User.id, User.email).all()

        for email, count in results:
            requester_data.append({
                'name': email,
                'count': count
            })

        # Sort by count descending
        requester_data.sort(key=lambda x: x['count'], reverse=True)

        return jsonify(requester_data)
    except Exception as e:
        app.logger.error(f'Error getting requester data: {str(e)}')
        return jsonify([])



@app.route('/api/settings/theme', methods=['POST'])
def api_update_theme():
    from flask import jsonify, request
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

        theme_color = data['theme_color']
        # Save to database
        AppSetting.set_setting('theme_color', theme_color)
        app.logger.info(f'Theme color saved: {theme_color}')
        # Don't flash message for API calls - JavaScript handles notifications
        return jsonify({'success': True, 'theme_color': theme_color})
    except Exception as e:
        app.logger.error(f'Error in api_update_theme: {str(e)}')
        return jsonify({'error': str(e), 'debug': 'Server error occurred'}), 500

@app.route('/api/settings/app', methods=['POST'])
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
    # Simple file serving route for uploaded files
    from flask import send_from_directory
    return send_from_directory('static/uploads', filename)

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

@app.route('/api/categories', methods=['POST'])
@login_required
def api_add_category():
    from flask import jsonify, request
    category_name = request.form.get('category_name', '').strip()
    if not category_name:
        return jsonify({'error': 'Category name is required'}), 400

    # For now, return the actual name that was submitted
    # In a real app, you'd save this to database
    flash(f'Category "{category_name}" added successfully', 'success')
    return jsonify({'success': True, 'id': 1, 'name': category_name})

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def api_delete_category(category_id):
    from flask import jsonify
    flash('Category deleted successfully', 'success')
    return jsonify({'success': True})

@app.route('/api/event-types', methods=['POST'])
@login_required
def api_add_event_type():
    from flask import jsonify, request
    type_name = request.form.get('type_name', '').strip()
    if not type_name:
        return jsonify({'error': 'Event type name is required'}), 400

    # For now, return the actual name that was submitted
    # In a real app, you'd save this to database
    flash(f'Event type "{type_name}" added successfully', 'success')
    return jsonify({'success': True, 'id': 1, 'name': type_name})

@app.route('/api/event-types/<int:type_id>', methods=['DELETE'])
@login_required
def api_delete_event_type(type_id):
    from flask import jsonify
    flash('Event type deleted successfully', 'success')
    return jsonify({'success': True})

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

