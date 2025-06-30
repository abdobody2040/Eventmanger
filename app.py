import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

class ProductionConfig:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '').replace(
        'postgres://', 'postgresql://')    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/app/static/uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB upload limit
# Configure logging
# logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask application
app = Flask(__name__)

# Configure application
app.secret_key = os.environ.get("SESSION_SECRET", "pharmaevents_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
# Use PostgreSQL if DATABASE_URL is available, otherwise fall back to SQLite for development
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    # Heroku workaround for SQLAlchemy 1.4+
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///pharmaevents.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB max upload

# Initialize SQLAlchemy with application
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# Create upload directory if it doesn't exist
with app.app_context():
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])

    # Import models and create tables
    from models import User, Event, EventCategory, EventType, Venue, ServiceRequest, EmployeeCode, AppSetting
    db.create_all()
    
    # Initialize default settings if they don't exist
    settings = {
        'app_name': 'PharmaEvents',
        'theme_color': 'blue'
    }
    
    for key, value in settings.items():
        if not AppSetting.query.filter_by(key=key).first():
            setting = AppSetting()
            setting.key = key
            setting.value = value
            db.session.add(setting)
    
    db.session.commit()

# Load user loader function
from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import routes to register them with the app
import routes
