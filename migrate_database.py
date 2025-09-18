#!/usr/bin/env python3
"""
VaultGuard Database Migration Script - FIXED VERSION
Run this ONCE to add missing columns to your existing database
"""

import sqlite3
import os
import sys
from datetime import datetime

def backup_database(db_path):
    """Create a backup of the database before migration"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"✅ Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Failed to backup database: {e}")
        return None

def get_table_names(cursor):
    """Get all table names in the database"""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"📋 Found tables: {', '.join(tables)}")
    return tables

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        return column_name in columns
    except:
        return False

def find_user_table(tables):
    """Find the user table (could be 'user', 'users', etc.)"""
    possible_names = ['user', 'users', 'User', 'Users']
    for name in possible_names:
        if name in tables:
            return name
    return None

def find_vault_table(tables):
    """Find the vault entry table"""
    possible_names = ['vault_entry', 'vault_entries', 'VaultEntry', 'password_entry', 'passwords']
    for name in possible_names:
        if name in tables:
            return name
    return None

def migrate_user_table(cursor, table_name):
    """Add missing columns to user table"""
    print(f"🔧 Migrating {table_name} table...")
    
    # First, get current columns
    cursor.execute(f"PRAGMA table_info({table_name})")
    current_columns = [row[1] for row in cursor.fetchall()]
    print(f"   Current columns: {', '.join(current_columns)}")
    
    # List of new columns to add
    new_columns = [
        ('email', 'VARCHAR(120)'),
        ('phone', 'VARCHAR(20)'),
        ('recovery_email', 'VARCHAR(120)'),
        ('recovery_phone', 'VARCHAR(20)'),
        ('last_password_change', 'DATETIME'),
        ('email_notifications', 'BOOLEAN DEFAULT 1'),
        ('sms_notifications', 'BOOLEAN DEFAULT 0'),
        ('security_alerts', 'BOOLEAN DEFAULT 1'),
        ('login_notifications', 'BOOLEAN DEFAULT 1'),
        ('breach_notifications', 'BOOLEAN DEFAULT 1'),
        ('two_factor_enabled', 'BOOLEAN DEFAULT 0'),
        ('two_factor_secret', 'VARCHAR(32)'),
        ('backup_codes', 'TEXT'),
        ('trusted_devices', 'TEXT')
    ]
    
    added_columns = 0
    for column_name, column_type in new_columns:
        if column_name not in current_columns:
            try:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                print(f"  ✅ Added column: {column_name}")
                added_columns += 1
            except Exception as e:
                print(f"  ❌ Failed to add {column_name}: {e}")
        else:
            print(f"  ✓ Column {column_name} already exists")
    
    # Set default values for existing users
    if added_columns > 0:
        try:
            # Set last_password_change to created_at for existing users
            cursor.execute(f"""
                UPDATE {table_name} 
                SET last_password_change = created_at 
                WHERE last_password_change IS NULL
            """)
            print("  ✅ Set default password change dates")
        except Exception as e:
            print(f"  ⚠️ Warning: Could not set default dates: {e}")
    
    return added_columns

def migrate_vault_entry_table(cursor, table_name):
    """Add missing columns to vault_entry table"""
    print(f"🔧 Migrating {table_name} table...")
    
    # First, get current columns
    cursor.execute(f"PRAGMA table_info({table_name})")
    current_columns = [row[1] for row in cursor.fetchall()]
    print(f"   Current columns: {', '.join(current_columns)}")
    
    # List of new columns to add
    new_columns = [
        ('category', "VARCHAR(50) DEFAULT 'General'"),
        ('notes', 'TEXT'),
        ('last_accessed', 'DATETIME'),
        ('password_strength_score', 'INTEGER DEFAULT 0'),
        ('is_compromised', 'BOOLEAN DEFAULT 0')
    ]
    
    added_columns = 0
    for column_name, column_type in new_columns:
        if column_name not in current_columns:
            try:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                print(f"  ✅ Added column: {column_name}")
                added_columns += 1
            except Exception as e:
                print(f"  ❌ Failed to add {column_name}: {e}")
        else:
            print(f"  ✓ Column {column_name} already exists")
    
    return added_columns

def create_new_tables(cursor):
    """Create new tables if they don't exist"""
    print("🔧 Creating new tables...")
    
    # Create SecurityLog table
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                description TEXT NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                severity VARCHAR(20) DEFAULT 'INFO',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("  ✅ Created SecurityLog table")
    except Exception as e:
        print(f"  ❌ Failed to create SecurityLog table: {e}")
    
    # Create PasswordReset table
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reset_token VARCHAR(100) UNIQUE NOT NULL,
                reset_method VARCHAR(20) NOT NULL,
                contact_info VARCHAR(120) NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("  ✅ Created PasswordReset table")
    except Exception as e:
        print(f"  ❌ Failed to create PasswordReset table: {e}")
    
    # Create DeviceFingerprint table
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_fingerprint (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_hash VARCHAR(64) NOT NULL,
                device_name VARCHAR(200),
                is_trusted BOOLEAN DEFAULT 0,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                user_agent TEXT
            )
        """)
        print("  ✅ Created DeviceFingerprint table")
    except Exception as e:
        print(f"  ❌ Failed to create DeviceFingerprint table: {e}")

def main():
    print("🛡️  VaultGuard Database Migration - FIXED VERSION")
    print("=" * 60)
    
    # Find database file
    db_files = [
        'instance/vaultguard_secure.db',
        'vaultguard_secure.db',
        'instance/passmanager.db',
        'passmanager.db',
        'instance/site.db',
        'site.db'
    ]
    
    db_path = None
    for path in db_files:
        if os.path.exists(path):
            db_path = path
            break
    
    if not db_path:
        print("❌ No database found! Please run your app.py first to create the database.")
        sys.exit(1)
    
    print(f"📄 Found database: {db_path}")
    
    # Connect and analyze database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get table information
        tables = get_table_names(cursor)
        user_table = find_user_table(tables)
        vault_table = find_vault_table(tables)
        
        print(f"👤 User table: {user_table or 'NOT FOUND'}")
        print(f"🗄️ Vault table: {vault_table or 'NOT FOUND'}")
        
        if not user_table:
            print("❌ Could not find user table. Your database structure is different.")
            print("   Available tables:", ', '.join(tables))
            sys.exit(1)
        
        # Ask for confirmation
        response = input(f"\n⚠️  This will modify your database ({db_path}). Continue? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Migration cancelled.")
            sys.exit(0)
        
        # Backup database
        backup_path = backup_database(db_path)
        if not backup_path:
            response = input("⚠️  Backup failed. Continue anyway? (y/N): ").strip().lower()
            if response != 'y':
                print("❌ Migration cancelled.")
                sys.exit(1)
        
        print("\n🚀 Starting migration...")
        
        # Migrate tables
        user_changes = migrate_user_table(cursor, user_table)
        vault_changes = 0
        if vault_table:
            vault_changes = migrate_vault_entry_table(cursor, vault_table)
        else:
            print("⚠️  No vault table found - skipping vault migration")
        
        create_new_tables(cursor)
        
        # Commit changes
        conn.commit()
        
        print("\n✅ Migration completed successfully!")
        print(f"   - Added {user_changes} columns to {user_table} table")
        print(f"   - Added {vault_changes} columns to {vault_table or 'N/A'} table")
        print(f"   - Created 3 new tables")
        
        if backup_path:
            print(f"\n💾 Original database backed up to: {backup_path}")
        
        print("\n🎉 Your database is now compatible with the enhanced features!")
        print("   You can now run your app.py normally.")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        if 'backup_path' in locals():
            print(f"💾 You can restore from backup: {backup_path}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()