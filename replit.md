# PharmaEvents - Event Management System

## Overview

PharmaEvents is a web-based event management application designed specifically for pharmaceutical companies to manage events while maintaining regulatory compliance. The system provides role-based access control with admin, event manager, and medical representative roles, along with comprehensive event creation, management, and reporting capabilities.

## System Architecture

### Frontend Architecture
- **Templates**: Jinja2-based HTML templates with Bootstrap 5.3.3 for responsive UI
- **CSS Framework**: Bootstrap with custom CSS variables for theming and dark mode support
- **JavaScript**: Vanilla JavaScript with jQuery for enhanced functionality
- **Component Libraries**:
  - Font Awesome 6.5.2 for icons
  - Select2 for enhanced select dropdowns
  - Chart.js 4.4.2 for dashboard analytics
  - Flatpickr for date/time pickers
- **Theme Support**: Light/dark mode toggle with CSS custom properties

### Backend Architecture
- **Framework**: Flask 3.1.1 with SQLAlchemy 2.0.40 ORM
- **Authentication**: Flask-Login for session management with role-based access control
- **Database**: PostgreSQL (production) with SQLite fallback (development)
- **File Handling**: Werkzeug for secure file uploads with 2MB limit
- **Deployment**: Gunicorn WSGI server with autoscale deployment target

### Database Schema
- **Users**: Email-based authentication with role hierarchy (admin > event_manager > medical_rep)
- **Events**: Comprehensive event model with online/offline support, categories, and venue management
- **Configuration**: AppSetting table for dynamic application configuration
- **Relationships**: Many-to-many associations between events and categories

## Key Components

### Authentication System
- Role-based access control with three user types
- Password hashing using Werkzeug security utilities
- Session-based authentication with Flask-Login
- Admin-only routes protected with custom decorators

### Event Management
- Full CRUD operations for events with rich metadata
- Support for both online and offline events
- Image upload with file validation and storage
- Multi-category tagging system
- Venue management with governorate-based filtering

### Dashboard & Analytics
- Real-time statistics with Chart.js visualizations
- Event filtering by date, category, and type
- Export functionality for compliance reporting
- Role-specific dashboard views

### File Management
- Secure file upload handling with extension validation
- Image storage in static/uploads directory
- 2MB file size limit enforcement
- Support for PNG, JPG, JPEG formats

## Data Flow

1. **User Authentication**: Login → Session Creation → Role Verification → Dashboard Redirect
2. **Event Creation**: Form Validation → File Upload Processing → Database Storage → Success Confirmation
3. **Event Management**: List View → Filter Application → CRUD Operations → Database Updates
4. **Analytics**: Data Aggregation → Chart Generation → Dashboard Display

## External Dependencies

### Python Packages
- **Flask Stack**: flask, flask-sqlalchemy, flask-login
- **Database**: psycopg2-binary for PostgreSQL connectivity
- **Validation**: email-validator for form validation
- **Deployment**: gunicorn for production serving

### Frontend Libraries
- **Bootstrap 5.3.3**: UI framework and components
- **Font Awesome 6.5.2**: Icon library
- **Chart.js 4.4.2**: Data visualization
- **Select2**: Enhanced select dropdowns
- **Flatpickr**: Date/time picker widgets

## Deployment Strategy

### Development Environment
- SQLite database for local development
- Flask development server with debug mode
- File-based session storage

### Production Environment
- PostgreSQL database with connection pooling
- Gunicorn WSGI server with 4 workers
- ProxyFix middleware for reverse proxy compatibility
- Environment-based configuration management

### Hosting Configuration
- **Modules**: python-3.11, postgresql-16
- **Port Mapping**: Internal 4000 → External 80
- **Process Management**: Parallel workflow execution
- **File Storage**: Static file serving for uploads

## Changelog

```
Changelog:
- June 30, 2025. Fixed application startup issues
  - Removed dotenv dependency causing import errors
  - Fixed Chart.js loading timing issues on dashboard
  - Fixed create_event template missing edit_mode variable
  - Enhanced user dropdown menu positioning and responsiveness
  - Added viewport boundary constraints for dropdown menus
  - Improved mobile device compatibility for navigation
- June 14, 2025. Initial setup
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```