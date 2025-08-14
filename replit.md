# PharmaEvents - Event Management System

## Overview
PharmaEvents is a web-based event management application tailored for pharmaceutical companies, focusing on regulatory compliance. It provides a robust platform for creating, managing, and reporting events with role-based access control (Admin, Event Manager, Medical Representative). The system aims to streamline event workflows, enhance data visualization, and ensure secure data handling for the pharmaceutical industry.

## User Preferences
Preferred communication style: Simple, everyday language.
Configuration: Environment variables only - no hardcoded values in source code.

## System Architecture

### Frontend Architecture
- **Templates**: Jinja2 with Bootstrap 5.3.3 for responsive UI.
- **CSS**: Bootstrap with custom variables for theming and dark mode.
- **JavaScript**: Vanilla JS and jQuery.
- **Libraries**: Font Awesome 6.5.2 (icons), Select2 (enhanced dropdowns), Chart.js 4.4.2 (analytics), Flatpickr (date/time pickers).
- **Theming**: Light/dark mode toggle via CSS custom properties.

### Backend Architecture
- **Framework**: Flask 3.1.1 with SQLAlchemy 2.0.40 ORM.
- **Authentication**: Flask-Login for session management and role-based access control.
- **Database**: PostgreSQL with strict connection validation.
- **File Handling**: Werkzeug for secure file uploads (2MB limit, specific image formats).
- **Deployment**: Gunicorn WSGI server with environment-based configuration.

### Database Schema
- **Users**: Email-based authentication with roles (admin, event_manager, medical_rep).
- **Events**: Comprehensive model supporting online/offline, categories, and venue management.
- **Configuration**: AppSetting for dynamic application settings.
- **Relationships**: Many-to-many associations for events and categories.

### Key Features
- **Authentication System**: Role-based access control, password hashing, session management, admin-only routes.
- **Event Management**: Full CRUD operations with rich metadata, image uploads, multi-category tagging, venue management, and a role-based approval workflow for events.
- **Dashboard & Analytics**: Real-time statistics with Chart.js, event filtering, export functionality, and role-specific views.
- **File Management**: Secure handling of image uploads with validation and storage.

### Data Flow
- **User Authentication**: Login → Session Creation → Role Verification → Dashboard Redirect.
- **Event Creation**: Form Validation → File Upload Processing → Database Storage → Success Confirmation.
- **Event Management**: List View → Filter Application → CRUD Operations → Database Updates.
- **Analytics**: Data Aggregation → Chart Generation → Dashboard Display.

### Deployment Strategy
- **Development**: PostgreSQL with connection validation, Flask development server.
- **Production**: PostgreSQL with connection pooling, Gunicorn (4 workers), ProxyFix middleware, environment-based configuration.
- **Hosting**: Python 3.11, PostgreSQL 16 modules, internal port 4000 mapped to external 80.

### Role-Based Access Control
- **Admin**: Full system access, can approve/decline all events, view all events and dashboard data.
- **Event Manager**: Can approve/decline events, view all events and dashboard data, no user management.
- **Medical Rep**: Can create events (starting in "pending" status), only view their own events and dashboard data.
- **Event Status Flow**: Medical Rep events require approval. Admins/Event Managers can create "active" events directly and manage approvals.

## External Dependencies

### Python Packages
- `flask`, `flask-sqlalchemy`, `flask-login`
- `psycopg2-binary` (for PostgreSQL)
- `email-validator`
- `gunicorn`

### Frontend Libraries
- Bootstrap 5.3.3
- Font Awesome 6.5.2
- Chart.js 4.4.2
- Select2
- Flatpickr

## Recent Changes

### August 13, 2025 - Migration Complete and Bug Fixes
- ✅ **Full Migration Completed**: Successfully migrated PharmaEvents from Replit Agent to standard Replit environment
- ✅ **Filter & Search Fix**: Fixed event filtering and search functionality on Events page - all filters now work properly
- ✅ **Category Management Fix**: Fixed adding new categories in Settings - properly saves to database with validation
- ✅ **Event Type Management Fix**: Fixed adding new event types in Settings - properly saves to database with validation  
- ✅ **Database Operations**: All API endpoints now properly create, validate, and delete categories/event types
- ✅ **JavaScript Enhancement**: Added complete client-side handling for all category and event type operations
- ✅ **Status Filter**: Added missing status filter handling for admin/event manager event filtering
- ✅ **Cache Integration**: All category/event type operations properly invalidate dashboard caches
- ✅ **Error Handling**: Added comprehensive error handling and user feedback for all operations

### August 13, 2025 - Replit Agent Migration and Bug Fixes
- ✅ **Full Migration Completed**: Successfully migrated PharmaEvents from Replit Agent to standard Replit environment
- ✅ **Filter & Search Fix**: Fixed event filtering and search functionality on Events page - all filters now work properly
- ✅ **Category Management Fix**: Fixed adding new categories in Settings - properly saves to database with validation
- ✅ **Event Type Management Fix**: Fixed adding new event types in Settings - properly saves to database with validation  
- ✅ **Database Operations**: All API endpoints now properly create, validate, and delete categories/event types
- ✅ **JavaScript Enhancement**: Added complete client-side handling for all category and event type operations
- ✅ **Status Filter**: Added missing status filter handling for admin/event manager event filtering
- ✅ **Cache Integration**: All category/event type operations properly invalidate dashboard caches
- ✅ **Error Handling**: Added comprehensive error handling and user feedback for all operations

### August 13, 2025 - Replit Agent Migration and Bug Fixes
- ✅ **Migration Completed**: Successfully migrated PharmaEvents from Replit Agent to standard Replit environment
- ✅ **Dependencies Installed**: Added all required Flask extensions (flask-wtf, flask-limiter, flask-caching, pillow, openpyxl, pandas, numpy, python-dotenv)
- ✅ **Database Setup**: Created PostgreSQL database and configured environment variables  
- ✅ **CSV Export Fix**: Fixed context error in events export functionality by converting SQLAlchemy objects to dictionaries within request context
- ✅ **Environment Configuration**: Set up SESSION_SECRET, ADMIN_EMAIL, and ADMIN_PASSWORD through Replit Secrets
- ✅ **Application Running**: Successfully deployed on port 5000 with Gunicorn WSGI server
- ✅ **Form Field Updates**: Made Venue Name, Employee Code, and Service Request ID required fields for event creation
- ✅ **Registration Deadline Logic**: Automatically calculates registration deadline as 2 days after event end date
- ✅ **UI Improvements**: Added readonly fields with helpful tooltips for auto-calculated registration deadlines
- ✅ **Backend Validation**: Updated server-side validation to enforce new required fields
- ✅ **JavaScript Enhancement**: Added automatic date calculation functionality with real-time updates
- ✅ **Logo Management**: Added remove logo functionality in application settings with confirmation dialog
- ✅ **API Enhancement**: Implemented DELETE endpoint for logo removal with file cleanup

### August 12, 2025 - Performance Optimization and Database Improvements
- ✅ **Database Optimization**: Added comprehensive database indexes for Event model including composite indexes for complex queries
- ✅ **Caching Layer**: Implemented Flask-Caching with 5-10 minute cache timeouts for dashboard statistics
- ✅ **Query Optimization**: Replaced inefficient N+1 queries with optimized aggregation using SQLAlchemy functions
- ✅ **Pagination Implementation**: Enhanced events listing with proper pagination (20 events per page, max 100)
- ✅ **Memory Optimization**: Implemented streaming CSV export with batch processing (100 events per batch)
- ✅ **Cache Invalidation**: Added automatic cache clearing when events are created, updated, deleted, or status changed
- ✅ **Performance Monitoring**: Added logging for cache operations and export progress tracking

### August 12, 2025 - Environment Migration and Bug Fixes
- ✅ Successfully migrated application from Replit Agent to standard Replit environment
- ✅ Removed all hardcoded credentials and configuration values from source code
- ✅ Implemented environment-variable-only configuration with python-dotenv support
- ✅ Created comprehensive .env.example template for development setup
- ✅ Added strict PostgreSQL connection validation with error handling
- ✅ Configured all Flask settings (host, port, debug, session) from environment variables
- ✅ Set up admin user creation exclusively from ADMIN_EMAIL and ADMIN_PASSWORD environment variables
- ✅ Application successfully validates required environment variables on startup
- ✅ Login system working with environment-configured admin credentials (NO hardcoded values)
- ✅ Dashboard displaying real event data (1 Oncology Conference event)
- ✅ Removed all unused files and duplicate code for clean environment-only configuration
- ✅ Fixed application name update functionality - corrected button ID mismatch in settings template

### Performance Optimization Benefits Achieved
- **Reduced Database Load**: Dashboard queries now use single aggregated queries instead of multiple separate queries
- **Faster Response Times**: Critical dashboard statistics cached for 5-10 minutes reducing database hits
- **Scalable Export**: Large event exports no longer cause memory issues with streaming implementation
- **Efficient Pagination**: Events listing supports up to 100 events per page with proper indexing
- **Smart Caching**: Automatic cache invalidation ensures data consistency while maintaining performance
- **Database Indexes**: 15+ strategic indexes covering all frequent query patterns including composite indexes for complex filters

### Migration Benefits Achieved
- Zero hardcoded sensitive information in codebase
- Proper separation of configuration from code
- Enhanced security with Replit Secrets integration
- Easy deployment across different environments
- Development-friendly with .env.example guidance