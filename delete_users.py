#!/usr/bin/env python3
"""
Delete Fake/Test Users from VaultGuard Database
Removes test users and their associated vault entries
FIXED: Handles sqlite_sequence table properly
"""
import sqlite3
import os
import sys
from datetime import datetime

# Database configuration
DB_FILE = os.path.join(os.path.dirname(__file__), 'vaultguard_secure.db')

def get_db_connection():
    """Get database connection"""
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
    """List all users in the database"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.created_at, 
                   COUNT(v.id) as password_count,
                   u.last_login,
                   u.failed_login_attempts
            FROM user u
            LEFT JOIN vault_entry v ON u.id = v.user_id
            GROUP BY u.id, u.username, u.created_at, u.last_login, u.failed_login_attempts
            ORDER BY u.created_at DESC
        """)
        
        users = cursor.fetchall()
        conn.close()
        return users
        
    except sqlite3.Error as e:
        print(f"❌ Error fetching users: {e}")
        conn.close()
        return []

def delete_user_by_id(user_id):
    """Delete a user and all their vault entries by ID"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # First, get user info for confirmation
        cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"❌ User with ID {user_id} not found!")
            conn.close()
            return False
        
        # Delete vault entries first (due to foreign key constraint)
        cursor.execute("DELETE FROM vault_entry WHERE user_id = ?", (user_id,))
        deleted_passwords = cursor.rowcount
        
        # Delete the user
        cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
        deleted_users = cursor.rowcount
        
        if deleted_users > 0:
            conn.commit()
            print(f"✅ Successfully deleted user '{user['username']}'")
            print(f"   🗑️  Removed {deleted_passwords} stored passwords")
            conn.close()
            return True
        else:
            print(f"❌ Failed to delete user with ID {user_id}")
            conn.close()
            return False
            
    except sqlite3.Error as e:
        print(f"❌ Error deleting user: {e}")
        conn.rollback()
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
            SELECT id, username FROM user 
            WHERE username LIKE ? 
            ORDER BY username
        """, (f'%{pattern}%',))
        
        matching_users = cursor.fetchall()
        
        if not matching_users:
            print(f"❌ No users found matching pattern '{pattern}'")
            conn.close()
            return 0
        
        print(f"Found {len(matching_users)} users matching pattern '{pattern}':")
        for user in matching_users:
            print(f"  - {user['username']} (ID: {user['id']})")
        
        # Confirm deletion
        confirm = input(f"\n⚠️  Are you sure you want to delete these {len(matching_users)} users? (yes/no): ").lower().strip()
        
        if confirm not in ['yes', 'y']:
            print("❌ Operation cancelled")
            conn.close()
            return 0
        
        deleted_count = 0
        total_passwords = 0
        
        for user in matching_users:
            # Count passwords for this user
            cursor.execute("SELECT COUNT(*) as count FROM vault_entry WHERE user_id = ?", (user['id'],))
            password_count = cursor.fetchone()['count']
            total_passwords += password_count
            
            # Delete vault entries
            cursor.execute("DELETE FROM vault_entry WHERE user_id = ?", (user['id'],))
            
            # Delete user
            cursor.execute("DELETE FROM user WHERE id = ?", (user['id'],))
            
            if cursor.rowcount > 0:
                deleted_count += 1
                print(f"✅ Deleted user '{user['username']}' and {password_count} passwords")
        
        conn.commit()
        conn.close()
        
        print(f"\n🎉 Successfully deleted {deleted_count} users and {total_passwords} total passwords")
        return deleted_count
        
    except sqlite3.Error as e:
        print(f"❌ Error deleting users: {e}")
        conn.rollback()
        conn.close()
        return 0

def delete_inactive_users(days=30):
    """Delete users who haven't logged in for X days"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        
        # Find inactive users (never logged in or no login in X days)
        cursor.execute("""
            SELECT id, username, created_at, last_login 
            FROM user 
            WHERE last_login IS NULL 
               OR datetime(last_login) < datetime('now', '-{} days')
            ORDER BY created_at
        """.format(days))
        
        inactive_users = cursor.fetchall()
        
        if not inactive_users:
            print(f"❌ No inactive users found (inactive = no login in {days} days)")
            conn.close()
            return 0
        
        print(f"Found {len(inactive_users)} inactive users (no login in {days} days):")
        for user in inactive_users:
            last_login = user['last_login'] if user['last_login'] else 'Never'
            print(f"  - {user['username']} (Created: {user['created_at']}, Last login: {last_login})")
        
        # Confirm deletion
        confirm = input(f"\n⚠️  Delete these {len(inactive_users)} inactive users? (yes/no): ").lower().strip()
        
        if confirm not in ['yes', 'y']:
            print("❌ Operation cancelled")
            conn.close()
            return 0
        
        deleted_count = 0
        total_passwords = 0
        
        for user in inactive_users:
            # Count passwords for this user
            cursor.execute("SELECT COUNT(*) as count FROM vault_entry WHERE user_id = ?", (user['id'],))
            password_count = cursor.fetchone()['count']
            total_passwords += password_count
            
            # Delete vault entries
            cursor.execute("DELETE FROM vault_entry WHERE user_id = ?", (user['id'],))
            
            # Delete user
            cursor.execute("DELETE FROM user WHERE id = ?", (user['id'],))
            
            if cursor.rowcount > 0:
                deleted_count += 1
                print(f"✅ Deleted inactive user '{user['username']}' and {password_count} passwords")
        
        conn.commit()
        conn.close()
        
        print(f"\n🎉 Successfully deleted {deleted_count} inactive users and {total_passwords} total passwords")
        return deleted_count
        
    except sqlite3.Error as e:
        print(f"❌ Error deleting inactive users: {e}")
        conn.rollback()
        conn.close()
        return 0

def delete_all_users():
    """Delete ALL users (DANGEROUS - for complete reset only)"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        
        # Count total users and passwords
        cursor.execute("SELECT COUNT(*) as count FROM user")
        total_users = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM vault_entry")
        total_passwords = cursor.fetchone()['count']
        
        if total_users == 0:
            print("❌ No users found in database")
            conn.close()
            return 0
        
        print(f"⚠️  DANGER: This will delete ALL {total_users} users and {total_passwords} passwords!")
        print("This action is IRREVERSIBLE and will completely reset the database!")
        
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
        
        # Delete all vault entries first
        cursor.execute("DELETE FROM vault_entry")
        deleted_passwords = cursor.rowcount
        
        # Delete all users
        cursor.execute("DELETE FROM user")
        deleted_users = cursor.rowcount
        
        # FIXED: Check if sqlite_sequence table exists before trying to delete from it
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
            if cursor.fetchone():
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='user'")
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='vault_entry'")
                print("   🔄 Reset auto-increment counters")
            else:
                print("   ℹ️  No auto-increment counters to reset")
        except sqlite3.Error as e:
            print(f"   ⚠️  Could not reset auto-increment counters: {e}")
        
        conn.commit()
        conn.close()
        
        print(f"\n💥 DATABASE RESET COMPLETE!")
        print(f"   👥 Deleted {deleted_users} users")
        print(f"   🔑 Deleted {deleted_passwords} passwords")
        
        return deleted_users
        
    except sqlite3.Error as e:
        print(f"❌ Error during mass deletion: {e}")
        conn.rollback()
        conn.close()
        return 0

def show_database_stats():
    """Show database statistics"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        
        # Get user count
        cursor.execute("SELECT COUNT(*) as count FROM user")
        user_count = cursor.fetchone()['count']
        
        # Get password count
        cursor.execute("SELECT COUNT(*) as count FROM vault_entry")
        password_count = cursor.fetchone()['count']
        
        # Get recent activity
        cursor.execute("""
            SELECT COUNT(*) as count FROM user 
            WHERE datetime(created_at) > datetime('now', '-7 days')
        """)
        recent_users = cursor.fetchone()['count']
        
        # Get locked accounts
        cursor.execute("""
            SELECT COUNT(*) as count FROM user 
            WHERE account_locked_until IS NOT NULL 
            AND datetime(account_locked_until) > datetime('now')
        """)
        locked_accounts = cursor.fetchone()['count']
        
        print("📊 VaultGuard Database Statistics")
        print("=" * 40)
        print(f"👥 Total Users: {user_count}")
        print(f"🔑 Total Passwords: {password_count}")
        print(f"🆕 New Users (7 days): {recent_users}")
        print(f"🔒 Locked Accounts: {locked_accounts}")
        
        if user_count > 0:
            avg_passwords = password_count / user_count
            print(f"📈 Average Passwords per User: {avg_passwords:.1f}")
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"❌ Error getting statistics: {e}")
        conn.close()

def main():
    """Main function with interactive menu"""
    print("🛡️  VaultGuard Database User Management")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        # Command line mode
        command = sys.argv[1].lower()
        
        if command == 'list':
            users = list_all_users()
            if users:
                print(f"\n📋 Found {len(users)} users:")
                print("-" * 80)
                for user in users:
                    last_login = user['last_login'] if user['last_login'] else 'Never'
                    failed_attempts = user['failed_login_attempts']
                    print(f"ID: {user['id']:3} | Username: {user['username']:20} | Passwords: {user['password_count']:2} | Created: {user['created_at'][:10]} | Last Login: {last_login:10} | Failed: {failed_attempts}")
        
        elif command == 'stats':
            show_database_stats()
            
        elif command == 'delete' and len(sys.argv) > 2:
            try:
                user_id = int(sys.argv[2])
                delete_user_by_id(user_id)
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
            delete_all_users()
            
        else:
            print("❌ Invalid command or missing arguments")
            print("\nUsage:")
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
        print("1. 📋 List all users")
        print("2. 📊 Show database statistics")
        print("3. 🗑️  Delete user by ID")
        print("4. 🔍 Delete users by username pattern")
        print("5. ⏰ Delete inactive users")
        print("6. 💥 Delete ALL users (RESET DATABASE)")
        print("7. ❌ Exit")
        
        try:
            choice = input("\nEnter your choice (1-7): ").strip()
            
            if choice == '1':
                users = list_all_users()
                if users:
                    print(f"\n📋 Found {len(users)} users:")
                    print("-" * 80)
                    for user in users:
                        last_login = user['last_login'] if user['last_login'] else 'Never'
                        failed_attempts = user['failed_login_attempts']
                        print(f"ID: {user['id']:3} | Username: {user['username']:20} | Passwords: {user['password_count']:2} | Created: {user['created_at'][:10]} | Last Login: {last_login:10} | Failed: {failed_attempts}")
                else:
                    print("📋 No users found in database")
            
            elif choice == '2':
                show_database_stats()
            
            elif choice == '3':
                try:
                    user_id = int(input("Enter user ID to delete: "))
                    delete_user_by_id(user_id)
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
                print("\n⚠️  WARNING: This will delete EVERYTHING!")
                delete_all_users()
            
            elif choice == '7':
                print("👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please enter 1-7.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Exiting...")
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")

if __name__ == "__main__":
    main()
