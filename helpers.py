import re
import csv
import io
from functools import wraps
from flask import flash, redirect, url_for, Response
from flask_login import current_user

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    """Check if a filename has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('This action requires administrator privileges', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
    
def not_medical_rep(f):
    """Decorator to restrict medical rep from accessing certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_medical_rep():
            flash('Medical representatives do not have access to this feature', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def export_events_to_csv(events):
    """Export events to a CSV file"""
    output = io.StringIO()
    fieldnames = [
        'id', 'name', 'requester_name', 'is_online', 'start_datetime', 
        'end_datetime', 'registration_deadline', 'governorate', 'venue', 
        'service_request', 'employee_code', 'event_type', 'description', 
        'created_at', 'created_by', 'approval_status', 'categories'
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for event in events:
        venue_name = event.venue_details.name if event.venue_details else None
        service_request_name = event.service_request.name if event.service_request else None
        employee_code = event.employee.code if event.employee else None
        event_type = event.event_type.name if event.event_type else None
        categories = ", ".join([c.name for c in event.categories]) if event.categories else ""
        
        writer.writerow({
            'id': event.id,
            'name': event.name,
            'requester_name': event.requester_name,
            'is_online': "Yes" if event.is_online else "No",
            'start_datetime': event.start_datetime.strftime('%Y-%m-%d %H:%M'),
            'end_datetime': event.end_datetime.strftime('%Y-%m-%d %H:%M'),
            'registration_deadline': event.registration_deadline.strftime('%Y-%m-%d %H:%M'),
            'governorate': event.governorate,
            'venue': venue_name,
            'service_request': service_request_name,
            'employee_code': employee_code,
            'event_type': event_type,
            'description': event.description,
            'created_at': event.created_at.strftime('%Y-%m-%d %H:%M'),
            'created_by': event.creator.email,
            'approval_status': event.status,
            'categories': categories
        })
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=events_export.csv"}
    )

def get_governorates():
    """Return list of governorates in Egypt"""
    return [
        'Alexandria', 'Aswan', 'Asyut', 'Beheira', 'Beni Suef', 
        'Cairo', 'Dakahlia', 'Damietta', 'Faiyum', 'Gharbia', 
        'Giza', 'Ismailia', 'Kafr El Sheikh', 'Luxor', 'Matruh', 
        'Minya', 'Monufia', 'New Valley', 'North Sinai', 'Port Said', 
        'Qalyubia', 'Qena', 'Red Sea', 'Sharqia', 'Sohag', 
        'South Sinai', 'Suez'
    ]

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def format_datetime(dt, format='%d %b %Y, %H:%M'):
    """Format datetime object to string"""
    if dt:
        return dt.strftime(format)
    return ''

def get_event_badge_class(is_online):
    """Return appropriate badge class based on event type"""
    return "bg-info" if is_online else "bg-success"
