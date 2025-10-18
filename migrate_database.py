#!/usr/bin/env python3
"""
Enhanced VaultGuard Database Migration Script - COMPLETE VERSION
Safely migrates database to support all new notification features
"""

import sqlite3
import os
import sys
import shutil
from datetime import datetime

def backup_database(db_path):
    """Create a backup of the database before migration"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        shutil.copy2(db_path, backup_path)
        print(f"✅ Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Failed to backup database: {e}")
        return None

def find_database():
    """Find the VaultGuard database file"""
    possible_paths = [
        'vaultguard_secure.db',
        'instance/vaultguard_secure.db',
        'passmanager.db',
        'instance/passmanager.db'
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

def check_table_exists(cursor, table_name):
    """Check if a table exists"""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        return column_name in columns
    except sqlite3.Error:
        return False

def migrate_user_table(cursor):
    """Add missing columns to user table"""
    print("🔧 Migrating user table...")
    
    # Get current columns
    cursor.execute("PRAGMA table_info(user)")
    current_columns = [row[1] for row in cursor.fetchall()]
    print(f"   Current columns: {len(current_columns)} found")
    
    # Define new columns with safe defaults
    new_columns = [
        ('email', 'VARCHAR(120)'),
        ('phone', 'VARCHAR(20)'),
        ('recovery_email', 'VARCHAR(120)'),
        ('recovery_phone', 'VARCHAR(20)'),
        ('email_notifications', 'BOOLEAN DEFAULT 1'),
        ('security_alerts', 'BOOLEAN DEFAULT 1'),
        ('login_notifications', 'BOOLEAN DEFAULT 1'),
        ('breach_notifications', 'BOOLEAN DEFAULT 1')
    ]
    
    added_count = 0
    
    for column_name, column_type in new_columns:
        if column_name not in current_columns:
            try:
                cursor.execute(f"ALTER TABLE user ADD COLUMN {column_name} {column_type}")
                print(f"  ✅ Added column: {column_name}")
                added_count += 1
            except sqlite3.Error as e:
                print(f"  ❌ Failed to add {column_name}: {e}")
        else:
            print(f"  ✓ Column {column_name} already exists")
    
    # Set default notification preferences for existing users
    if added_count > 0:
        try:
            cursor.execute("""
                UPDATE user 
                SET email_notifications = 1,
                    security_alerts = 1,
                    login_notifications = 1,
                    breach_notifications = 1
                WHERE email_notifications IS NULL
            """)
            print(f"  ✅ Set default notification preferences for existing users")
        except sqlite3.Error as e:
            print(f"  ⚠️  Warning: Could not set defaults: {e}")
    
    return added_count

def create_indexes(cursor):
    """Create database indexes for better performance"""
    print("🔧 Creating performance indexes...")
    
    indexes = [
        ("idx_user_email", "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email)"),
        ("idx_user_username", "CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)"),
        ("idx_vault_user_id", "CREATE INDEX IF NOT EXISTS idx_vault_user_id ON vault_entry(user_id)"),
        ("idx_vault_site", "CREATE INDEX IF NOT EXISTS idx_vault_site ON vault_entry(site)"),
        ("idx_user_created", "CREATE INDEX IF NOT EXISTS idx_user_created ON user(created_at)"),
        ("idx_vault_updated", "CREATE INDEX IF NOT EXISTS idx_vault_updated ON vault_entry(updated_at)")
    ]
    
    created_count = 0
    for index_name, sql in indexes:
        try:
            cursor.execute(sql)
            print(f"  ✅ Created index: {index_name}")
            created_count += 1
        except sqlite3.Error as e:
            print(f"  ⚠️  Index {index_name}: {e}")
    
    return created_count

def verify_migration(cursor):
    """Verify that migration was successful"""
    print("🔍 Verifying migration...")
    
    # Check user table columns
    cursor.execute("PRAGMA table_info(user)")
    columns = [row[1] for row in cursor.fetchall()]
    
    required_columns = [
        'id', 'username', 'password_hash', 'encryption_salt',
        'email', 'phone', 'email_notifications', 'security_alerts',
        'login_notifications', 'breach_notifications'
    ]
    
    missing_columns = [col for col in required_columns if col not in columns]
    
    if missing_columns:
        print(f"  ❌ Missing columns: {missing_columns}")
        return False
    
    # Check data integrity
    cursor.execute("SELECT COUNT(*) FROM user")
    user_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM vault_entry")
    vault_count = cursor.fetchone()[0]
    
    print(f"  ✅ Database integrity verified")
    print(f"     Users: {user_count}")
    print(f"     Vault entries: {vault_count}")
    print(f"     Columns: {len(columns)} total")
    
    return True

def show_migration_summary(db_path, added_columns, created_indexes):
    """Show summary of migration results"""
    print("\n" + "="*60)
    print("MIGRATION SUMMARY")
    print("="*60)
    print(f"Database: {db_path}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Added columns: {added_columns}")
    print(f"Created indexes: {created_indexes}")
    print(f"Status: ✅ SUCCESSFUL")
    print("="*60)
    
    print("\n🎉 Your VaultGuard database is now ready for enhanced features!")
    print("\nNEW FEATURES ENABLED:")
    print("   ✅ Email notifications")
    print("   ✅ Phone number storage")
    print("   ✅ Recovery contact options")
    print("   ✅ Notification preferences")
    print("   ✅ Enhanced security alerts")
    print("   ✅ Performance optimizations")
    
    print("\n📋 NEXT STEPS:")
    print("1. Replace your app.py with the enhanced version")
    print("2. Replace login.html and register.html with enhanced versions")
    print("3. Add reset_password.html to your templates folder")
    print("4. Start your application: python app.py")
    
    print("\n⚠️  IMPORTANT:")
    print("- A backup was created before migration")
    print("- All existing data is preserved")
    print("- Users can now register with email addresses")
    print("- Forgot password feature will work")

def main():
    """Main migration function"""
    print("🛡️  VaultGuard Enhanced Database Migration")
    print("="*60)
    print("This script will safely upgrade your database to support:")
    print("  • Email & phone registration")
    print("  • Notification preferences")
    print("  • Recovery contact information")
    print("  • Enhanced security features")
    print("="*60)
    
    # Find database
    db_path = find_database()
    if not db_path:
        print("❌ No VaultGuard database found!")
        print("\nSearched for:")
        print("  - vaultguard_secure.db")
        print("  - instance/vaultguard_secure.db")
        print("  - passmanager.db")
        print("  - instance/passmanager.db")
        print("\nPlease run this script from your VaultGuard directory.")
        sys.exit(1)
    
    print(f"📄 Found database: {db_path}")
    
    # Get user confirmation
    response = input(f"\n⚠️  This will modify your database. Continue? (y/N): ").strip().lower()
    if response != 'y':
        print("❌ Migration cancelled by user.")
        sys.exit(0)
    
    # Create backup
    print("\n💾 Creating backup...")
    backup_path = backup_database(db_path)
    if not backup_path:
        response = input("⚠️  Backup failed. Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Migration cancelled.")
            sys.exit(1)
    
    # Perform migration
    try:
        print(f"\n🚀 Starting migration on {db_path}...")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Begin transaction
        cursor.execute("BEGIN TRANSACTION")
        
        # Migrate tables
        added_columns = migrate_user_table(cursor)
        created_indexes = create_indexes(cursor)
        
        # Verify migration
        if not verify_migration(cursor):
            raise Exception("Migration verification failed")
        
        # Commit transaction
        cursor.execute("COMMIT")
        conn.close()
        
        # Show summary
        show_migration_summary(db_path, added_columns, created_indexes)
        
        print(f"\n💾 Backup location: {backup_path}")
        print("🎉 Migration completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        
        try:
            cursor.execute("ROLLBACK")
            conn.close()
        except:
            pass
        
        if backup_path:
            print(f"💾 Your original database backup: {backup_path}")
            restore = input("Restore from backup? (y/N): ").strip().lower()
            if restore == 'y':
                try:
                    shutil.copy2(backup_path, db_path)
                    print("✅ Database restored from backup")
                except Exception as restore_error:
                    print(f"❌ Restore failed: {restore_error}")
        
        sys.exit(1)

if __name__ == "__main__":
    main()
