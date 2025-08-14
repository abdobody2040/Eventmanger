
#!/usr/bin/env python3
"""
Database migration script to add missing columns to the event table
"""

import os
from sqlalchemy import create_engine, text, inspect
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    print("ERROR: DATABASE_URL not found in environment variables")
    exit(1)

# Create engine
engine = create_engine(database_url)

def migrate_database():
    """Add missing columns to the event table"""
    
    try:
        with engine.connect() as connection:
            # Check which columns already exist
            inspector = inspect(engine)
            existing_columns = [col['name'] for col in inspector.get_columns('event')]
            print(f"Existing columns in event table: {existing_columns}")
            
            migrations = []
            
            # Check and add venue_name column
            if 'venue_name' not in existing_columns:
                migrations.append("ALTER TABLE event ADD COLUMN venue_name VARCHAR(200);")
            else:
                print("✓ venue_name column already exists")
            
            # Check and add employee_code column  
            if 'employee_code' not in existing_columns:
                migrations.append("ALTER TABLE event ADD COLUMN employee_code VARCHAR(50);")
            else:
                print("✓ employee_code column already exists")
            
            # Check and add service_request_id column
            if 'service_request_id' not in existing_columns:
                migrations.append("ALTER TABLE event ADD COLUMN service_request_id VARCHAR(100);")
            else:
                print("✓ service_request_id column already exists")
            
            if not migrations:
                print("✓ All required columns already exist - no migrations needed!")
                return True
            
            # Start transaction
            trans = connection.begin()
            
            try:
                for migration in migrations:
                    print(f"Executing: {migration}")
                    connection.execute(text(migration))
                
                # Commit all changes
                trans.commit()
                print("✓ All migrations completed successfully!")
                
            except Exception as e:
                trans.rollback()
                print(f"✗ Migration failed: {str(e)}")
                raise
                
    except Exception as e:
        print(f"✗ Database connection failed: {str(e)}")
        return False
        
    return True

if __name__ == "__main__":
    print("Starting database migration...")
    success = migrate_database()
    if success:
        print("Database migration completed successfully!")
    else:
        print("Database migration failed!")
        exit(1)
