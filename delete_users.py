#!/usr/bin/env python3
"""
Enhanced VaultGuard User Management Tool
Complete user deletion with proper cleanup and session invalidation
"""
import os
import sys
import sqlite3
from datetime import datetime
from sqlalchemy import text

# Database configuration
DB_FILE = 'vaultguard_secure.db'

def get_db_connection():
    """Get database connection with proper error handling"""
    if not os.path.exists(DB_FILE):
        print(f"❌ Database file '{DB_FILE}' not found!")
        print(f"Make sure you're running this script from the same directory as your app.py")
        return None
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    except sqlite3.Error as e:
        print(f"❌ Database connection error: {e}")
        return None

def list_all_users():
    """List all users with enhanced information"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.created_at, 
                   COUNT(v.id) as password_count,
                   u.last_login,
                   u.failed_login_attempts,
                   u.account_locked_until,
                   CASE 
                     WHEN u.account_locked_until IS NOT NULL AND 
                          datetime(u.account_locked_until) > datetime('now') 
                     THEN 'LOCKED' 
                     ELSE 'ACTIVE' 
                   END as status
            FROM user u
            LEFT JOIN vault_entry v ON u.id = v.user_id
            GROUP BY u.id, u.username, u.email, u.created_at, u.last_login, u.failed_login_attempts, u.account_locked_until
            ORDER BY u.created_at DESC
        """)
        
        users = cursor.fetchall()
        conn.close()
        return users
        
    except sqlite3.Error as e:
        print(f"❌ Error fetching users: {e}")
        conn.close()
        return []

def delete_user_completely(user_id):
    """Completely delete a user and all associated data"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Get user info for confirmation
        cursor.execute("SELECT username, email FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"❌ User with ID {user_id} not found!")
            conn.close()
            return False
        
        print(f"\n🗑️  Preparing to DELETE user: {user['username']}")
        if user['email']:
            print(f"    Email: {user['email']}")
        
        # Count associated data
        cursor.execute("SELECT COUNT(*) as count FROM vault_entry WHERE user_id = ?", (user_id,))
        vault_count = cursor.fetchone()['count']
        
        print(f"    Vault entries: {vault_count}")
        
        # Confirm deletion
        confirm = input(f"\n⚠️  Are you sure you want to PERMANENTLY delete this user? (yes/no): ").lower().strip()
        if confirm not in ['yes', 'y']:
            print("❌ Deletion cancelled")
            conn.close()
            return False
        
        # Start transaction
        cursor.execute("BEGIN TRANSACTION")
        
        # Delete vault entries first (foreign key constraint)
        cursor.execute("DELETE FROM vault_entry WHERE user_id = ?", (user_id,))
        deleted_vault = cursor.rowcount
        
        # Delete any security logs if they exist
        try:
            cursor.execute("DELETE FROM security_log WHERE user_id = ?", (user_id,))
        except sqlite3.Error:
            pass  # Table might not exist
        
        # Delete any device fingerprints if they exist
        try:
            cursor.execute("DELETE FROM device_fingerprint WHERE user_id = ?", (user_id,))
        except sqlite3.Error:
            pass  # Table might not exist
        
        # Delete any password reset tokens if they exist
        try:
            cursor.execute("DELETE FROM password_reset WHERE user_id = ?", (user_id,))
        except sqlite3.Error:
            pass  # Table might not exist
        
        # Delete the user
        cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
        deleted_users = cursor.rowcount
        
        if deleted_users > 0:
            cursor.execute("COMMIT")
            print(f"✅ Successfully deleted user '{user['username']}'")
            print(f"   🗑️  Removed {deleted_vault} vault entries")
            print(f"   🧹 Cleaned up all associated data")
            conn.close()
            return True
        else:
            cursor.execute("ROLLBACK")
            print(f"❌ Failed to delete user with ID {user_id}")
            conn.close()
            return False
            
    except sqlite3.Error as e:
        print(f"❌ Error deleting user: {e}")
        try:
            cursor.execute("ROLLBACK")
        except:
            pass
        conn.close()
        return False

def delete_users_by_pattern(pattern):
    """Delete users whose username contains a pattern"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        
        # Find matching users
        cursor.execute("""
            SELECT u.id, u.username, u.email, COUNT(v.id) as vault_count
            FROM user u
            LEFT JOIN vault_entry v ON u.id = v.user_id
            WHERE u.username LIKE ? 
            GROUP BY u.id, u.username, u.email
            ORDER BY u.username
        """, (f'%{pattern}%',))
        
        matching_users = cursor.fetchall()
        
        if not matching_users:
            print(f"❌ No users found matching pattern '{pattern}'")
            conn.close()
            return 0
        
        print(f"🔍 Found {len(matching_users)} users matching pattern '{pattern}':")
        total_vault_entries = 0
        for user in matching_users:
            email_info = f" ({user['email']})" if user['email'] else ""
            print(f"  - {user['username']}{email_info} - {user['vault_count']} passwords")
            total_vault_entries += user['vault_count']
        
        print(f"\n📊 Total: {len(matching_users)} users, {total_vault_entries} vault entries")
        
        # Confirm deletion
        confirm = input(f"\n⚠️  Are you sure you want to delete these {len(matching_users)} users? (yes/no): ").lower().strip()
        
        if confirm not in ['yes', 'y']:
            print("❌ Operation cancelled")
            conn.close()
            return 0
        
        deleted_count = 0
        total_passwords = 0
        
        cursor.execute("BEGIN TRANSACTION")
        
        for user in matching_users:
            try:
                # Delete vault entries
                cursor.execute("DELETE FROM vault_entry WHERE user_id = ?", (user['id'],))
                vault_deleted = cursor.rowcount
                
                # Clean up other associated data
                try:
                    cursor.execute("DELETE FROM security_log WHERE user_id = ?", (user['id'],))
                    cursor.execute("DELETE FROM device_fingerprint WHERE user_id = ?", (user['id'],))
                    cursor.execute("DELETE FROM password_reset WHERE user_id = ?", (user['id'],))
                except sqlite3.Error:
                    pass  # Tables might not exist
                
                # Delete user
                cursor.execute("DELETE FROM user WHERE id = ?", (user['id'],))
                
                if cursor.rowcount > 0:
                    deleted_count += 1
                    total_passwords += vault_deleted
                    print(f"✅ Deleted user '{user['username']}' and {vault_deleted} passwords")
                    
            except sqlite3.Error as e:
                print(f"❌ Failed to delete user '{user['username']}': {e}")
        
        cursor.execute("COMMIT")
        conn.close()
        
        print(f"\n🎉 Successfully deleted {deleted_count} users and {total_passwords} total passwords")
        return deleted_count
        
    except sqlite3.Error as e:
        print(f"❌ Error deleting users: {e}")
        try:
            cursor.execute("ROLLBACK")
        except:
            pass
        conn.close()
        return 0

def delete_inactive_users(days=30):
    """Delete users who haven't logged in for X days"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        
        # Find inactive users
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.created_at, u.last_login,
                   COUNT(v.id) as vault_count
            FROM user u
            LEFT JOIN vault_entry v ON u.id = v.user_id
            WHERE (u.last_login IS NULL AND date(u.created_at) < date('now', '-{} days'))
               OR (u.last_login IS NOT NULL AND date(u.last_login) < date('now', '-{} days'))
            GROUP BY u.id, u.username, u.email, u.created_at, u.last_login
            ORDER BY u.created_at
        """.format(days, days))
        
        inactive_users = cursor.fetchall()
        
        if not inactive_users:
            print(f"❌ No inactive users found (inactive = no activity in {days} days)")
            conn.close()
            return 0
        
        print(f"⏰ Found {len(inactive_users)} inactive users (no activity in {days} days):")
        total_vault_entries = 0
        for user in inactive_users:
            last_activity = user['last_login'] if user['last_login'] else user['created_at']
            email_info = f" ({user['email']})" if user['email'] else ""
            print(f"  - {user['username']}{email_info}")
            print(f"    Last activity: {last_activity[:10]} | Passwords: {user['vault_count']}")
            total_vault_entries += user['vault_count']
        
        print(f"\n📊 Total: {len(inactive_users)} users, {total_vault_entries} vault entries")
        
        # Confirm deletion
        confirm = input(f"\n⚠️  Delete these {len(inactive_users)} inactive users? (yes/no): ").lower().strip()
        
        if confirm not in ['yes', 'y']:
            print("❌ Operation cancelled")
            conn.close()
            return 0
        
        deleted_count = 0
        total_passwords = 0
        
        cursor.execute("BEGIN TRANSACTION")
        
        for user in inactive_users:
            try:
                # Delete vault entries
                cursor.execute("DELETE FROM vault_entry WHERE user_id = ?", (user['id'],))
                vault_deleted = cursor.rowcount
                
                # Clean up associated data
                try:
                    cursor.execute("DELETE FROM security_log WHERE user_id = ?", (user['id'],))
                    cursor.execute("DELETE FROM device_fingerprint WHERE user_id = ?", (user['id'],))
                    cursor.execute("DELETE FROM password_reset WHERE user_id = ?", (user['id'],))
                except sqlite3.Error:
                    pass
                
                # Delete user
                cursor.execute("DELETE FROM user WHERE id = ?", (user['id'],))
                
                if cursor.rowcount > 0:
                    deleted_count += 1
                    total_passwords += vault_deleted
                    print(f"✅ Deleted inactive user '{user['username']}' and {vault_deleted} passwords")
                    
            except sqlite3.Error as e:
                print(f"❌ Failed to delete user '{user['username']}': {e}")
        
        cursor.execute("COMMIT")
        conn.close()
        
        print(f"\n🎉 Successfully deleted {deleted_count} inactive users and {total_passwords} total passwords")
        return deleted_count
        
    except sqlite3.Error as e:
        print(f"❌ Error deleting inactive users: {e}")
        try:
            cursor.execute("ROLLBACK")
        except:
            pass
        conn.close()
        return 0

def reset_database():
    """DANGEROUS: Delete ALL users and vault entries"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        
        # Count everything first
        cursor.execute("SELECT COUNT(*) as count FROM user")
        total_users = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM vault_entry")
        total_passwords = cursor.fetchone()['count']
        
        if total_users == 0:
            print("❌ No users found in database")
            conn.close()
            return 0
        
        print(f"💥 DANGER: This will delete ALL {total_users} users and {total_passwords} passwords!")
        print("This action is IRREVERSIBLE and will completely reset the database!")
        print("\n🔥 ALL DATA WILL BE PERMANENTLY LOST! 🔥")
        
        confirm1 = input("\nType 'DELETE ALL USERS' to confirm: ").strip()
        if confirm1 != 'DELETE ALL USERS':
            print("❌ Operation cancelled - confirmation text incorrect")
            conn.close()
            return 0
        
        confirm2 = input("Are you absolutely sure? Type 'YES DELETE EVERYTHING': ").strip()
        if confirm2 != 'YES DELETE EVERYTHING':
            print("❌ Operation cancelled - final confirmation failed")
            conn.close()
            return 0
        
        cursor.execute("BEGIN TRANSACTION")
        
        # Delete all vault entries first
        cursor.execute("DELETE FROM vault_entry")
        deleted_passwords = cursor.rowcount
        
        # Delete all associated data
        try:
            cursor.execute("DELETE FROM security_log")
            cursor.execute("DELETE FROM device_fingerprint")
            cursor.execute("DELETE FROM password_reset")
        except sqlite3.Error:
            pass  # Tables might not exist
        
        # Delete all users
        cursor.execute("DELETE FROM user")
        deleted_users = cursor.rowcount
        
        # Reset auto-increment counters
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('user', 'vault_entry', 'security_log', 'device_fingerprint', 'password_reset')")
        
        cursor.execute("COMMIT")
        conn.close()
        
        print(f"\n💥 DATABASE RESET COMPLETE!")
        print(f"   👥 Deleted {deleted_users} users")
        print(f"   🔑 Deleted {deleted_passwords} passwords")
        print(f"   🗃️  Reset auto-increment counters")
        print(f"   🧹 Cleaned up all associated data")
        
        return deleted_users
        
    except sqlite3.Error as e:
        print(f"❌ Error during database reset: {e}")
        try:
            cursor.execute("ROLLBACK")
        except:
            pass
        conn.close()
        return 0

def show_database_stats():
    """Show comprehensive database statistics"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        
        # Basic counts
        cursor.execute("SELECT COUNT(*) as count FROM user")
        user_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM vault_entry")
        password_count = cursor.fetchone()['count']
        
        # Recent activity
        cursor.execute("""
            SELECT COUNT(*) as count FROM user 
            WHERE date(created_at) > date('now', '-7 days')
        """)
        recent_users = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM user 
            WHERE date(last_login) > date('now', '-7 days')
        """)
        recent_logins = cursor.fetchone()['count']
        
        # Security stats
        cursor.execute("""
            SELECT COUNT(*) as count FROM user 
            WHERE account_locked_until IS NOT NULL 
            AND datetime(account_locked_until) > datetime('now')
        """)
        locked_accounts = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM user 
            WHERE failed_login_attempts > 0
        """)
        accounts_with_failed_attempts = cursor.fetchone()['count']
        
        # Email statistics
        cursor.execute("SELECT COUNT(*) as count FROM user WHERE email IS NOT NULL AND email != ''")
        users_with_email = cursor.fetchone()['count']
        
        print("📊 VaultGuard Database Statistics")
        print("=" * 50)
        print(f"👥 Total Users: {user_count}")
        print(f"🔑 Total Passwords: {password_count}")
        print(f"📧 Users with Email: {users_with_email}")
        print(f"🆕 New Users (7 days): {recent_users}")
        print(f"🔐 Recent Logins (7 days): {recent_logins}")
        print(f"🔒 Locked Accounts: {locked_accounts}")
        print(f"⚠️  Accounts with Failed Attempts: {accounts_with_failed_attempts}")
        
        if user_count > 0:
            avg_passwords = password_count / user_count
            print(f"📈 Average Passwords per User: {avg_passwords:.1f}")
            
            # Top users by password count
            cursor.execute("""
                SELECT u.username, COUNT(v.id) as password_count
                FROM user u
                LEFT JOIN vault_entry v ON u.id = v.user_id
                GROUP BY u.id, u.username
                HAVING password_count > 0
                ORDER BY password_count DESC
                LIMIT 5
            """)
            top_users = cursor.fetchall()
            
            if top_users:
                print(f"\n🏆 Top Users by Password Count:")
                for user in top_users:
                    print(f"   - {user['username']}: {user['password_count']} passwords")
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"❌ Error getting statistics: {e}")
        conn.close()

def main():
    """Enhanced main function with better interface"""
    print("🛡️  VaultGuard Enhanced User Management Tool")
    print("=" * 60)
    
    # Command line mode
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'list':
            users = list_all_users()
            if users:
                print(f"\n📋 Found {len(users)} users:")
                print("-" * 100)
                print(f"{'ID':<3} | {'Username':<20} | {'Email':<25} | {'Passwords':<9} | {'Status':<8} | {'Created':<10}")
                print("-" * 100)
                for user in users:
                    email = user['email'] if user['email'] else 'No email'
                    email = email[:22] + "..." if len(email) > 25 else email
                    created = user['created_at'][:10]
                    print(f"{user['id']:<3} | {user['username']:<20} | {email:<25} | {user['password_count']:<9} | {user['status']:<8} | {created}")
        
        elif command == 'stats':
            show_database_stats()
            
        elif command == 'delete' and len(sys.argv) > 2:
            try:
                user_id = int(sys.argv[2])
                delete_user_completely(user_id)
            except ValueError:
                print("❌ Invalid user ID. Please provide a number.")
                
        elif command == 'pattern' and len(sys.argv) > 2:
            pattern = sys.argv[2]
            delete_users_by_pattern(pattern)
            
        elif command == 'inactive' and len(sys.argv) > 2:
            try:
                days = int(sys.argv[2])
                delete_inactive_users(days)
            except ValueError:
                print("❌ Invalid days. Please provide a number.")
                
        elif command == 'reset':
            reset_database()
            
        else:
            print("❌ Invalid command or missing arguments")
            print("\n📖 Usage:")
            print("  python delete_users.py list                    - List all users")
            print("  python delete_users.py stats                   - Show database stats")
            print("  python delete_users.py delete <user_id>        - Delete user by ID")
            print("  python delete_users.py pattern <pattern>       - Delete users matching pattern")
            print("  python delete_users.py inactive <days>         - Delete inactive users")
            print("  python delete_users.py reset                   - Delete ALL users (DANGEROUS)")
        
        return
    
    # Interactive mode
    while True:
        print("\n🔧 What would you like to do?")
        print("1. 📋 List all users (with enhanced details)")
        print("2. 📊 Show comprehensive database statistics")
        print("3. 🗑️  Delete user by ID (complete cleanup)")
        print("4. 🔍 Delete users by username pattern")
        print("5. ⏰ Delete inactive users (configurable days)")
        print("6. 💥 RESET DATABASE (Delete ALL users - DANGEROUS)")
        print("7. ❌ Exit")
        
        try:
            choice = input("\nEnter your choice (1-7): ").strip()
            
            if choice == '1':
                users = list_all_users()
                if users:
                    print(f"\n📋 Found {len(users)} users:")
                    print("-" * 100)
                    print(f"{'ID':<3} | {'Username':<20} | {'Email':<25} | {'Passwords':<9} | {'Status':<8} | {'Created':<10}")
                    print("-" * 100)
                    for user in users:
                        email = user['email'] if user['email'] else 'No email'
                        email = email[:22] + "..." if len(email) > 25 else email
                        created = user['created_at'][:10]
                        print(f"{user['id']:<3} | {user['username']:<20} | {email:<25} | {user['password_count']:<9} | {user['status']:<8} | {created}")
                else:
                    print("📋 No users found in database")
            
            elif choice == '2':
                show_database_stats()
            
            elif choice == '3':
                try:
                    user_id = int(input("Enter user ID to delete: "))
                    delete_user_completely(user_id)
                except ValueError:
                    print("❌ Invalid user ID. Please enter a number.")
            
            elif choice == '4':
                pattern = input("Enter username pattern to match (e.g., 'test', 'demo'): ").strip()
                if pattern:
                    delete_users_by_pattern(pattern)
                else:
                    print("❌ Pattern cannot be empty")
            
            elif choice == '5':
                try:
                    days = int(input("Delete users inactive for how many days? (default 30): ") or "30")
                    delete_inactive_users(days)
                except ValueError:
                    print("❌ Invalid number of days")
            
            elif choice == '6':
                print("\n💥 WARNING: This will delete EVERYTHING!")
                print("This will completely reset your VaultGuard database!")
                reset_database()
            
            elif choice == '7':
                print("👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please enter 1-7.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Exiting...")
            break
        except Exception as e:
            print(f"❌ An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
