import os
import re
import uuid
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db
from models import User, Event, EventCategory, EventType, Venue, ServiceRequest, EmployeeCode, AppSetting
from helpers import allowed_file, get_governorates, admin_required, not_medical_rep, export_events_to_csv

# Routes for authentication
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Get app name for login template
    app_name_setting = AppSetting.query.filter_by(key='app_name').first()
    app_name = app_name_setting.value if app_name_setting else 'PharmaEvents'
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Invalid email or password', 'danger')
            return render_template('login.html', app_name=app_name)
        
        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html', app_name=app_name)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # Get app name for login template
    app_name_setting = AppSetting.query.filter_by(key='app_name').first()
    app_name = app_name_setting.value if app_name_setting else 'PharmaEvents'
    
    # This would typically send a password reset email
    flash('Password reset functionality is not implemented yet', 'info')
    return redirect(url_for('login'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    # Get counts - filter by user role for upcoming events
    upcoming_events_count_query = Event.query.filter(Event.start_datetime > datetime.utcnow())
    if not current_user.is_admin():
        upcoming_events_count_query = upcoming_events_count_query.filter(
            db.or_(
                Event.status == 'approved',
                Event.user_id == current_user.id
            )
        )
    upcoming_events = upcoming_events_count_query.count()
    
    online_events = Event.query.filter_by(is_online=True).count()
    offline_events = Event.query.filter_by(is_online=False).count()
    total_events = Event.query.count()
    
    # Get pending events count for admin
    pending_events_count = 0
    pending_events_list = []
    if current_user.is_admin():
        pending_events_count = Event.query.filter_by(status='pending').count()
        pending_events_list = Event.query.filter_by(status='pending').order_by(Event.created_at.desc()).limit(5).all()
    
    # Get categories for chart
    categories = EventCategory.query.all()
    category_data = []
    for category in categories:
        count = Event.query.filter(Event.categories.contains(category)).count()
        if count > 0:
            category_data.append({
                'name': category.name,
                'count': count
            })
    
    # Get upcoming events
    upcoming_events_query = Event.query.filter(Event.start_datetime > datetime.utcnow())
    
    # Filter by status depending on user role
    if not current_user.is_admin():
        # Regular users only see approved events or their own
        upcoming_events_query = upcoming_events_query.filter(
            db.or_(
                Event.status == 'approved',
                Event.user_id == current_user.id
            )
        )
    else:
        # Admins see all upcoming events regardless of status
        pass
    
    upcoming_events_list = upcoming_events_query.order_by(Event.start_datetime).limit(5).all()
    
    # Get recent events
    recent_events = Event.query.order_by(Event.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                          upcoming_events_count=upcoming_events,
                          online_events=online_events,
                          offline_events=offline_events,
                          total_events=total_events,
                          pending_events_count=pending_events_count,
                          pending_events_list=pending_events_list,
                          category_data=category_data,
                          upcoming_events_list=upcoming_events_list,
                          recent_events=recent_events)

# Events routes
@app.route('/events')
@login_required
def events():
    # Get filter parameters
    search = request.args.get('search', '')
    category_id = request.args.get('category', 'all')
    event_type_id = request.args.get('type', 'all')
    date_filter = request.args.get('date', 'all')
    status_filter = request.args.get('status', 'all')
    
    # Base query
    query = Event.query
    
    # For medical reps, only show their own events
    if current_user.is_medical_rep():
        query = query.filter_by(user_id=current_user.id)
    
    # Apply filters
    if search:
        query = query.filter(Event.name.ilike(f'%{search}%'))
    
    if category_id != 'all' and category_id.isdigit():
        category = EventCategory.query.get(int(category_id))
        if category:
            query = query.filter(Event.categories.contains(category))
    
    if event_type_id != 'all' and event_type_id.isdigit():
        query = query.filter_by(event_type_id=int(event_type_id))
        
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    # Date filtering logic
    if date_filter == 'upcoming':
        query = query.filter(Event.start_datetime > datetime.utcnow())
    elif date_filter == 'past':
        query = query.filter(Event.start_datetime <= datetime.utcnow())
    
    # Execute query
    events_list = query.order_by(Event.start_datetime.desc()).all()
    
    # Get categories and types for filters
    categories = EventCategory.query.all()
    event_types = EventType.query.all()
    
    return render_template('events.html', 
                          events=events_list,
                          categories=categories,
                          event_types=event_types,
                          selected_category=category_id,
                          selected_type=event_type_id,
                          selected_date=date_filter,
                          selected_status=status_filter,
                          search_query=search)
                          
@app.route('/events/export')
@login_required
@not_medical_rep
def export_events():
    # Get the same filters as in the events route
    search = request.args.get('search', '')
    category_id = request.args.get('category', 'all')
    event_type_id = request.args.get('type', 'all')
    date_filter = request.args.get('date', 'all')
    status_filter = request.args.get('status', 'all')
    
    # Base query
    query = Event.query
    
    # Apply filters
    if search:
        query = query.filter(Event.name.ilike(f'%{search}%'))
    
    if category_id != 'all' and category_id.isdigit():
        category = EventCategory.query.get(int(category_id))
        if category:
            query = query.filter(Event.categories.contains(category))
    
    if event_type_id != 'all' and event_type_id.isdigit():
        query = query.filter_by(event_type_id=int(event_type_id))
        
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    # Date filtering logic
    if date_filter == 'upcoming':
        query = query.filter(Event.start_datetime > datetime.utcnow())
    elif date_filter == 'past':
        query = query.filter(Event.start_datetime <= datetime.utcnow())
    
    # Execute query
    events_list = query.order_by(Event.start_datetime.desc()).all()
    
    # Generate CSV response
    return export_events_to_csv(events_list)

@app.route('/events/<int:event_id>')
@login_required
def event_details(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_details.html', event=event)

@app.route('/create-event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        # Extract form data
        name = request.form.get('event_name')
        requester_name = request.form.get('requester_name')
        is_online = 'is_online' in request.form
        start_date = request.form.get('start_date')
        start_time = request.form.get('start_time')
        end_date = request.form.get('end_date')
        end_time = request.form.get('end_time')
        deadline_date = request.form.get('deadline_date')
        deadline_time = request.form.get('deadline_time')
        governorate = request.form.get('governorate')
        venue_id = request.form.get('venue_id') if request.form.get('venue_id') else None
        service_request_id = request.form.get('service_request_id') if request.form.get('service_request_id') else None
        employee_code_id = request.form.get('employee_code_id') if request.form.get('employee_code_id') else None
        category_ids = request.form.getlist('categories')
        event_type_id = request.form.get('event_type')
        description = request.form.get('description')
        
        # Validate required fields
        if not all([name, requester_name, start_date, start_time, end_date, end_time, 
                   deadline_date, deadline_time, event_type_id, category_ids, description]):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('create_event'))
            
        if not requester_name or len(requester_name) < 4:
            flash('Requester name must be at least 4 characters long', 'danger')
            return redirect(url_for('create_event'))
        
        # Parse dates and times
        try:
            # Validate that all date/time fields are present
            if not all([start_date, start_time, end_date, end_time, deadline_date, deadline_time]):
                flash('All date and time fields are required.', 'danger')
                return redirect(url_for('create_event'))
                
            # Validate date/time format
            date_pattern = r'^\d{4}-\d{2}-\d{2}$'
            time_pattern = r'^\d{2}:\d{2}$'
            
            # Validate that all required fields are strings and match patterns
            date_time_fields = [
                (start_date, date_pattern, "start date"),
                (start_time, time_pattern, "start time"),
                (end_date, date_pattern, "end date"),
                (end_time, time_pattern, "end time"),
                (deadline_date, date_pattern, "deadline date"),
                (deadline_time, time_pattern, "deadline time")
            ]
            
            for field_value, pattern, field_name in date_time_fields:
                if not field_value or not isinstance(field_value, str) or not re.match(pattern, field_value):
                    flash(f'Invalid {field_name} format. Please use the date/time selectors.', 'danger')
                    return redirect(url_for('create_event'))
            
            # All validations passed, continue with processing
            if False:  # This condition will never be true, but maintains the original structure
                flash('Invalid date or time format. Please use the date/time selectors.', 'danger')
                return redirect(url_for('create_event'))
                
            # Parse the datetime objects
            start_datetime = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
            end_datetime = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M")
            registration_deadline = datetime.strptime(f"{deadline_date} {deadline_time}", "%Y-%m-%d %H:%M")
            
            # Additional date validation
            if end_datetime < start_datetime:
                flash('End date must be after or equal to start date', 'danger')
                return redirect(url_for('create_event'))
                
            if registration_deadline > start_datetime:
                flash('Registration deadline must be on or before the event start date', 'danger')
                return redirect(url_for('create_event'))
                
        except ValueError as e:
            # Print the specific error to help with debugging
            print(f"Date parsing error: {str(e)}")
            flash('Invalid date or time format. Please ensure all dates and times are correctly formatted.', 'danger')
            return redirect(url_for('create_event'))
        
        # Set event status based on user role
        status = 'pending'
        if current_user.is_admin():
            status = 'approved'  # Admins' events are auto-approved
            
        # Create new event
        event = Event()
        event.name = name
        event.requester_name = requester_name
        event.is_online = is_online
        event.start_datetime = start_datetime
        event.end_datetime = end_datetime
        event.registration_deadline = registration_deadline
        event.governorate = governorate if not is_online else None
        event.venue_id = venue_id if venue_id and not is_online else None
        event.service_request_id = service_request_id
        event.employee_code_id = employee_code_id
        event.event_type_id = event_type_id
        event.description = description
        event.user_id = current_user.id
        event.status = status
        
        # Add categories
        for category_id in category_ids:
            category = EventCategory.query.get(int(category_id))
            if category:
                event.categories.append(category)
        
        # Handle image upload
        image_url = request.form.get('image_url')
        if image_url:
            event.image_url = image_url
        elif 'event_banner' in request.files:
            file = request.files['event_banner']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Generate unique filename
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                event.image_file = unique_filename
        
        # Save to database
        db.session.add(event)
        db.session.commit()
        
        # Show appropriate message
        if status == 'pending':
            flash('Event created successfully! It will be visible after administrator approval.', 'success')
        else:
            flash('Event created successfully!', 'success')
            
        return redirect(url_for('events'))
    
    # GET request - show the form
    categories = EventCategory.query.all()
    event_types = EventType.query.all()
    venues = Venue.query.all()
    service_requests = ServiceRequest.query.all()
    employee_codes = EmployeeCode.query.all()
    governorates = get_governorates()
    
    return render_template('create_event.html',
                          categories=categories,
                          event_types=event_types,
                          venues=venues,
                          service_requests=service_requests,
                          employee_codes=employee_codes,
                          governorates=governorates)

@app.route('/edit-event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user is authorized to edit this event
    if event.user_id != current_user.id and not current_user.is_admin():
        flash('You are not authorized to edit this event', 'danger')
        return redirect(url_for('events'))
    
    if request.method == 'POST':
        # Extract form data (similar to create_event)
        event.name = request.form.get('event_name')
        event.requester_name = request.form.get('requester_name')
        event.is_online = 'is_online' in request.form
        
        # Parse dates and times
        try:
            start_date = request.form.get('start_date')
            start_time = request.form.get('start_time')
            end_date = request.form.get('end_date')
            end_time = request.form.get('end_time')
            deadline_date = request.form.get('deadline_date')
            deadline_time = request.form.get('deadline_time')
            
            event.start_datetime = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
            event.end_datetime = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M")
            event.registration_deadline = datetime.strptime(f"{deadline_date} {deadline_time}", "%Y-%m-%d %H:%M")
        except ValueError:
            flash('Invalid date or time format', 'danger')
            return redirect(url_for('edit_event', event_id=event_id))
        
        # Update other fields
        if event.is_online:
            event.governorate = None
            event.venue_id = None
        else:
            event.governorate = request.form.get('governorate')
            venue_id = request.form.get('venue_id')
            event.venue_id = int(venue_id) if venue_id and venue_id.isdigit() else None
        
        service_request_text = request.form.get('service_request')
        employee_code_text = request.form.get('employee_code')
        event_type_id = request.form.get('event_type')
        
        # Handle free text service request
        if service_request_text:
            service_request = ServiceRequest.query.filter_by(name=service_request_text).first()
            if not service_request:
                service_request = ServiceRequest()
                service_request.name = service_request_text
                db.session.add(service_request)
                db.session.flush()
            event.service_request_id = service_request.id
        else:
            event.service_request_id = None
            
        # Handle free text employee code
        if employee_code_text:
            employee_code = EmployeeCode.query.filter_by(code=employee_code_text).first()
            if not employee_code:
                employee_code = EmployeeCode()
                employee_code.code = employee_code_text
                employee_code.name = employee_code_text
                db.session.add(employee_code)
                db.session.flush()
            event.employee_code_id = employee_code.id
        else:
            event.employee_code_id = None
        if event_type_id and event_type_id.isdigit():
            event.event_type_id = int(event_type_id)
        else:
            event.event_type_id = None
        event.description = request.form.get('description')
        
        # Check if status change was requested (only admins can change status)
        if current_user.is_admin() and 'event_status' in request.form:
            event.status = request.form.get('event_status')
        
        # If not admin and event was modified, set status back to pending for review
        if not current_user.is_admin() and event.status == 'approved':
            event.status = 'pending'
            flash('Your changes will need to be approved by an administrator', 'info')
        
        # Update categories
        event.categories = []
        category_ids = request.form.getlist('categories')
        for category_id in category_ids:
            category = EventCategory.query.get(int(category_id))
            if category:
                event.categories.append(category)
        
        # Handle image update
        image_url = request.form.get('image_url')
        if image_url:
            event.image_url = image_url
            event.image_file = None
        elif 'event_banner' in request.files and request.files['event_banner'].filename:
            file = request.files['event_banner']
            if file and file.filename and allowed_file(file.filename):
                # Remove old file if it exists
                if event.image_file:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], event.image_file)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                # Save new file
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                event.image_file = unique_filename
                event.image_url = None
        
        # Save changes
        db.session.commit()
        flash('Event updated successfully!', 'success')
        return redirect(url_for('events'))
    
    # GET request - show the form with current data
    categories = EventCategory.query.all()
    event_types = EventType.query.all()
    venues = Venue.query.all()
    service_requests = ServiceRequest.query.all()
    employee_codes = EmployeeCode.query.all()
    governorates = get_governorates()
    
    return render_template('create_event.html',
                          event=event,
                          categories=categories,
                          event_types=event_types,
                          venues=venues,
                          service_requests=service_requests,
                          employee_codes=employee_codes,
                          governorates=governorates,
                          edit_mode=True)

@app.route('/delete-event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Only admins can delete events
    if not current_user.is_admin():
        flash('You are not authorized to delete this event', 'danger')
        return redirect(url_for('events'))
    
    # Delete uploaded file if it exists
    if event.image_file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], event.image_file)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    # Delete event
    db.session.delete(event)
    db.session.commit()
    
    flash('Event deleted successfully!', 'success')
    return redirect(url_for('events'))

# Settings routes
@app.route('/settings')
@login_required
def settings():
    # Only admins can access settings
    if not current_user.is_admin():
        flash('You are not authorized to access settings', 'danger')
        return redirect(url_for('dashboard'))
    
    categories = EventCategory.query.all()
    event_types = EventType.query.all()
    users = User.query.all()
    
    # Get app settings
    app_name = AppSetting.query.filter_by(key='app_name').first()
    theme = AppSetting.query.filter_by(key='theme').first()
    
    return render_template('settings.html',
                          categories=categories,
                          event_types=event_types,
                          users=users,
                          app_name=app_name.value if app_name else 'PharmaEvents',
                          theme=theme.value if theme else 'light')
                          
# API endpoints for settings
@app.route('/api/settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Handle theme toggle
    if 'theme' in data and data['theme'] in ['light', 'dark']:
        theme_setting = AppSetting.query.filter_by(key='theme').first()
        if not theme_setting:
            theme_setting = AppSetting()
            theme_setting.key = 'theme'
            theme_setting.value = 'light'
            db.session.add(theme_setting)
        theme_setting.value = data['theme']
        db.session.commit()  # Commit the change immediately
    
    # Handle app name change
    if 'name' in data and data['name'] and data['name'].strip():
        name_setting = AppSetting.query.filter_by(key='app_name').first()
        if not name_setting:
            name_setting = AppSetting()
            name_setting.key = 'app_name'
            name_setting.value = 'PharmaEvents'
            db.session.add(name_setting)
        name_setting.value = data['name'].strip()
        db.session.commit()  # Commit the change immediately
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/settings/logo', methods=['POST'])
@login_required
@admin_required
def update_logo():
    if 'logo' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
        
    file = request.files['logo']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
        
    if file and file.filename and allowed_file(file.filename):
        # Ensure filename is not None before passing to secure_filename
        original_filename = file.filename or "upload"
        filename = secure_filename(original_filename)
        # Generate unique filename
        unique_filename = f"logo_{uuid.uuid4()}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        
        # Update or create logo setting
        logo_setting = AppSetting.query.filter_by(key='app_logo').first()
        if not logo_setting:
            logo_setting = AppSetting()
            logo_setting.key = 'app_logo'
            logo_setting.value = unique_filename
            db.session.add(logo_setting)
        else:
            # Remove old logo file if it exists
            if logo_setting.value:
                old_logo_path = os.path.join(app.config['UPLOAD_FOLDER'], logo_setting.value)
                if os.path.exists(old_logo_path):
                    os.remove(old_logo_path)
            
            logo_setting.value = unique_filename
        
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Invalid file type'})

@app.route('/api/categories', methods=['POST'])
@login_required
def add_category():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    name = request.form.get('category_name')
    if not name:
        return jsonify({"error": "Category name is required"}), 400
    
    # Check if category already exists
    existing = EventCategory.query.filter_by(name=name).first()
    if existing:
        return jsonify({"error": "Category already exists"}), 400
    
    # Create new category
    category = EventCategory()
    category.name = name
    db.session.add(category)
    db.session.commit()
    
    return jsonify({"id": category.id, "name": category.name}), 201

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    category = EventCategory.query.get_or_404(category_id)
    
    # Check if category is being used
    if category.events:
        return jsonify({"error": "Cannot delete category as it is being used by events"}), 400
    
    # Delete category
    db.session.delete(category)
    db.session.commit()
    
    return jsonify({"message": "Category deleted successfully"}), 200

@app.route('/api/event-types', methods=['POST'])
@login_required
def add_event_type():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    name = request.form.get('type_name')
    if not name:
        return jsonify({"error": "Event type name is required"}), 400
    
    # Check if event type already exists
    existing = EventType.query.filter_by(name=name).first()
    if existing:
        return jsonify({"error": "Event type already exists"}), 400
    
    # Create new event type
    event_type = EventType()
    event_type.name = name
    db.session.add(event_type)
    db.session.commit()
    
    return jsonify({"id": event_type.id, "name": event_type.name}), 201

@app.route('/api/event-types/<int:type_id>', methods=['DELETE'])
@login_required
def delete_event_type(type_id):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    event_type = EventType.query.get_or_404(type_id)
    
    # Check if event type is being used
    if event_type.events:
        return jsonify({"error": "Cannot delete event type as it is being used by events"}), 400
    
    # Delete event type
    db.session.delete(event_type)
    db.session.commit()
    
    return jsonify({"message": "Event type deleted successfully"}), 200

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if not all([email, password, role]):
        return jsonify({"error": "All fields are required"}), 400
    
    # Check if user already exists
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": "User with this email already exists"}), 400
    
    # Create new user
    user = User()
    user.email = email
    user.role = role
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"id": user.id, "email": user.email, "role": user.role}), 201

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    # Cannot delete yourself
    if user_id == current_user.id:
        return jsonify({"error": "Cannot delete your own account"}), 400
    
    user = User.query.get_or_404(user_id)
    
    # Check if user has events
    events = Event.query.filter_by(user_id=user_id).all()
    if events:
        # Either reassign events to current admin or handle differently
        for event in events:
            event.user_id = current_user.id
        db.session.commit()
    
    # Now delete the user
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"message": "User deleted successfully"}), 200

# API routes for charts and data
@app.route('/api/dashboard/statistics')
@login_required
def dashboard_statistics():
    try:
        # Get counts for dashboard
        upcoming_events = Event.query.filter(Event.start_datetime > datetime.utcnow()).count()
        online_events = Event.query.filter_by(is_online=True).count()
        offline_events = Event.query.filter_by(is_online=False).count()
        total_events = Event.query.count()
        pending_events = Event.query.filter_by(status='pending').count() if current_user.is_admin() else 0
        
        return jsonify({
            "upcoming_events": upcoming_events,
            "online_events": online_events,
            "offline_events": offline_events,
            "total_events": total_events,
            "pending_events": pending_events
        })
    except Exception as e:
        app.logger.error(f"Dashboard statistics error: {str(e)}")
        return jsonify({
            "upcoming_events": 0,
            "online_events": 0,
            "offline_events": 0,
            "total_events": 0,
            "pending_events": 0
        }), 500

@app.route('/api/dashboard/categories')
@login_required
def dashboard_categories():
    # Get category data for chart
    categories = EventCategory.query.all()
    data = []
    
    for category in categories:
        count = Event.query.filter(Event.categories.contains(category)).count()
        if count > 0:
            data.append({
                "name": category.name,
                "count": count
            })
    
    return jsonify(data)

@app.route('/api/dashboard/monthly-events')
@login_required
def monthly_events():
    # Get monthly event counts for the past year
    now = datetime.utcnow()
    
    # Initialize data structure for the past 12 months
    months = []
    counts = []
    
    for i in range(11, -1, -1):
        year = now.year
        month = now.month - i
        
        if month <= 0:
            month += 12
            year -= 1
        
        # Get count for this month
        start_date = datetime(year, month, 1)
        
        # Calculate end date (first day of next month)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)
        
        count = Event.query.filter(Event.start_datetime >= start_date, 
                                   Event.start_datetime < end_date).count()
        
        # Format month name
        month_name = start_date.strftime('%b %Y')
        
        months.append(month_name)
        counts.append(count)
    
    return jsonify({
        "labels": months,
        "data": counts
    })

@app.route('/api/dashboard/events-by-requester')
@login_required
def events_by_requester():
    # Get top requesters
    requesters = db.session.query(
        Event.requester_name, 
        db.func.count(Event.id).label('count')
    ).group_by(Event.requester_name).order_by(db.desc('count')).limit(5).all()
    
    data = []
    for requester in requesters:
        data.append({
            "name": requester.requester_name,
            "count": requester.count
        })
    
    return jsonify(data)

# Uploads handler
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route to update database schema (for when we add new columns)
@app.route('/migrate-db', methods=['GET'])
def migrate_db():
    from app import db
    
    # Drop and recreate all tables
    db.drop_all()
    db.create_all()
    
    # Create admin user
    admin = User()
    admin.email = os.environ.get('ADMIN_EMAIL')
    admin.role = os.environ.get('ADMIN_ROLE')
    admin.set_password(os.environ.get('ADMIN_PASSWORD'))
    
    # Create event manager user
    event_manager = User()
    event_manager.email = os.environ.get('EVENT_MANAGER_EMAIL')
    event_manager.role = os.environ.get('EVENT_MANAGER_ROLE')
    event_manager.set_password(os.environ.get('EVENT_MANAGER_PASSWORD'))
    
    # Create medical rep user
    medical_rep = User()
    medical_rep.email = os.environ.get('MEDICAL_REP_EMAIL')
    medical_rep.role = os.environ.get('MEDICAL_REP_ROLE')
    medical_rep.set_password(os.environ.get('MEDICAL_REP_PASSWORD'))
    
    # Add users to session
    db.session.add(admin)
    db.session.add(event_manager)
    db.session.add(medical_rep)
    
    # Create event categories
    categories = [
        'Cardiology', 'Oncology', 'Neurology', 'Pediatrics', 
        'Endocrinology', 'Dermatology', 'Psychiatry', 'Product Launch',
        'Medical Education', 'Patient Awareness', 'Internal Training'
    ]
    
    for cat_name in categories:
        category = EventCategory()
        category.name = cat_name
        db.session.add(category)
    
    # Create event types
    event_types = [
        'Conference', 'Webinar', 'Workshop', 'Symposium', 
        'Roundtable Meeting', 'Investigator Meeting'
    ]
    
    for type_name in event_types:
        event_type = EventType()
        event_type.name = type_name
        db.session.add(event_type)
    
    # Create venues
    venues = [
        {'name': 'Nile Conference Hall', 'governorate': 'Cairo'},
        {'name': 'Alexandria Medical Center', 'governorate': 'Alexandria'},
        {'name': 'Luxor International Conference Center', 'governorate': 'Luxor'},
        {'name': 'Children\'s Hospital Auditorium', 'governorate': 'Alexandria'},
        {'name': 'Mansoura University Hospital', 'governorate': 'Dakahlia'}
    ]
    
    for venue_data in venues:
        venue = Venue()
        venue.name = venue_data['name']
        venue.governorate = venue_data['governorate']
        db.session.add(venue)
    
    # Create service requests
    service_requests = ['Clinical Trial Support', 'Product Education', 'Physician Training']
    for sr_name in service_requests:
        sr = ServiceRequest()
        sr.name = sr_name
        db.session.add(sr)
    
    # Create employee codes
    employee_codes = [
        {'code': 'EMP001', 'name': 'John Doe'},
        {'code': 'EMP002', 'name': 'Jane Smith'},
        {'code': 'EMP003', 'name': 'Ahmed Hassan'}
    ]
    
    for ec_data in employee_codes:
        ec = EmployeeCode()
        ec.code = ec_data['code']
        ec.name = ec_data['name']
        db.session.add(ec)
    
    # Commit changes
    db.session.commit()
    
    flash('Database schema has been updated successfully!', 'success')
    return redirect(url_for('dashboard'))

# Make app settings available to all templates
@app.context_processor
def inject_settings():
    app_name = AppSetting.query.filter_by(key='app_name').first()
    theme = AppSetting.query.filter_by(key='theme').first()
    
    return {
        'app_name': app_name.value if app_name else 'PharmaEvents',
        'theme': theme.value if theme else 'light'
    }

# Initialize database with seed data    
@app.route('/init-db', methods=['GET'])
def init_db():
    # Check if database already has data
    if User.query.count() > 0:
        return "Database already initialized"
    
    # Create admin user
    admin = User()
    admin.email = os.environ.get('ADMIN_EMAIL')
    admin.role = os.environ.get('ADMIN_ROLE')
    admin.set_password(os.environ.get('ADMIN_PASSWORD'))
    
    # Create event manager user
    event_manager = User()
    event_manager.email = 'manager@pharmaevents.com'
    event_manager.role = 'event_manager'
    event_manager.set_password('manager123')
    
    # Add users to session
    db.session.add(admin)
    db.session.add(event_manager)
    
    # Create event categories
    categories = [
        'Cardiology', 'Oncology', 'Neurology', 'Pediatrics', 
        'Endocrinology', 'Dermatology', 'Psychiatry', 'Product Launch',
        'Medical Education', 'Patient Awareness', 'Internal Training'
    ]
    
    for cat_name in categories:
        category = EventCategory()
        category.name = cat_name
        db.session.add(category)
    
    # Create event types
    event_types = [
        'Conference', 'Webinar', 'Workshop', 'Symposium', 
        'Roundtable Meeting', 'Investigator Meeting'
    ]
    
    for type_name in event_types:
        event_type = EventType()
        event_type.name = type_name
        db.session.add(event_type)
    
    # Create venues
    venues = [
        {'name': 'Nile Conference Hall', 'governorate': 'Cairo'},
        {'name': 'Alexandria Medical Center', 'governorate': 'Alexandria'},
        {'name': 'Luxor International Conference Center', 'governorate': 'Luxor'},
        {'name': 'Children\'s Hospital Auditorium', 'governorate': 'Alexandria'},
        {'name': 'Mansoura University Hospital', 'governorate': 'Dakahlia'}
    ]
    
    for venue_data in venues:
        venue = Venue()
        venue.name = venue_data['name']
        venue.governorate = venue_data['governorate']
        db.session.add(venue)
    
    # Create service requests
    service_requests = ['Clinical Trial Support', 'Product Education', 'Physician Training']
    for sr_name in service_requests:
        sr = ServiceRequest()
        sr.name = sr_name
        db.session.add(sr)
    
    # Create employee codes
    employee_codes = [
        {'code': 'EMP001', 'name': 'John Doe'},
        {'code': 'EMP002', 'name': 'Jane Smith'},
        {'code': 'EMP003', 'name': 'Ahmed Hassan'}
    ]
    
    for ec_data in employee_codes:
        ec = EmployeeCode()
        ec.code = ec_data['code']
        ec.name = ec_data['name']
        db.session.add(ec)
    
    # Commit changes
    db.session.commit()
    
    return "Database initialized with seed data!"

# Event approval routes
@app.route('/events/<int:event_id>/approve')
@login_required
@admin_required
def approve_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    if event.status != 'pending':
        flash('This event is not pending approval.', 'warning')
        return redirect(url_for('events'))
    
    event.status = 'approved'
    db.session.commit()
    
    flash(f'Event "{event.name}" has been approved.', 'success')
    return redirect(request.referrer or url_for('events', status='pending'))

# Event rejection route
@app.route('/events/<int:event_id>/reject')
@login_required
@admin_required
def reject_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    if event.status != 'pending':
        flash('This event is not pending approval.', 'warning')
        return redirect(url_for('events'))
    
    event.status = 'rejected'
    db.session.commit()
    
    flash(f'Event "{event.name}" has been rejected.', 'warning')
    return redirect(request.referrer or url_for('events', status='pending'))
