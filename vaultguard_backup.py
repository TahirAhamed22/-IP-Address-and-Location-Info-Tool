#!/usr/bin/env python3
"""
VaultGuard Database Backup Script
Creates encrypted backups of the database with rotation
"""
import os
import sqlite3
import json
import zipfile
import shutil
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_backup_key(master_password):
    """Generate encryption key for backup"""
    salt = b'vaultguard_backup_salt_2024'  # Static salt for backup consistency
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def create_backup(db_path='vaultguard_secure.db', backup_password=None):
    """Create encrypted database backup"""
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found!")
        return False
    
    if not backup_password:
        backup_password = input("Enter backup encryption password: ")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = 'backups'
    os.makedirs(backup_dir, exist_ok=True)
    
    # Create backup metadata
    backup_info = {
        'timestamp': timestamp,
        'database_file': db_path,
        'backup_version': '1.0',
        'encrypted': True
    }
    
    try:
        # Copy database to temp location
        temp_db = f"temp_backup_{timestamp}.db"
        shutil.copy2(db_path, temp_db)
        
        # Create ZIP archive
        backup_zip = f"{backup_dir}/vaultguard_backup_{timestamp}.zip"
        with zipfile.ZipFile(backup_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(temp_db, 'database.db')
            zf.writestr('backup_info.json', json.dumps(backup_info, indent=2))
        
        # Encrypt the backup
        backup_key = generate_backup_key(backup_password)
        fernet = Fernet(backup_key)
        
        with open(backup_zip, 'rb') as f:
            backup_data = f.read()
        
        encrypted_backup = fernet.encrypt(backup_data)
        encrypted_backup_path = f"{backup_dir}/vaultguard_backup_{timestamp}.encrypted"
        
        with open(encrypted_backup_path, 'wb') as f:
            f.write(encrypted_backup)
        
        # Cleanup
        os.remove(temp_db)
        os.remove(backup_zip)
        
        print(f"Encrypted backup created: {encrypted_backup_path}")
        return True
        
    except Exception as e:
        print(f"Backup failed: {e}")
        # Cleanup on failure
        if os.path.exists(temp_db):
            os.remove(temp_db)
        if os.path.exists(backup_zip):
            os.remove(backup_zip)
        return False

def restore_backup(backup_path, backup_password, restore_path='vaultguard_restored.db'):
    """Restore database from encrypted backup"""
    if not os.path.exists(backup_path):
        print(f"Backup file {backup_path} not found!")
        return False
    
    try:
        # Decrypt backup
        backup_key = generate_backup_key(backup_password)
        fernet = Fernet(backup_key)
        
        with open(backup_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Extract ZIP
        temp_zip = 'temp_restore.zip'
        with open(temp_zip, 'wb') as f:
            f.write(decrypted_data)
        
        with zipfile.ZipFile(temp_zip, 'r') as zf:
            # Read backup info
            backup_info = json.loads(zf.read('backup_info.json'))
            print(f"Restoring backup from: {backup_info['timestamp']}")
            
            # Extract database
            zf.extract('database.db', '.')
            shutil.move('database.db', restore_path)
        
        # Cleanup
        os.remove(temp_zip)
        
        print(f"Database restored to: {restore_path}")
        return True
        
    except Exception as e:
        print(f"Restore failed: {e}")
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return False

def cleanup_old_backups(backup_dir='backups', keep_count=10):
    """Remove old backup files, keeping only the most recent ones"""
    if not os.path.exists(backup_dir):
        return
    
    backup_files = [f for f in os.listdir(backup_dir) if f.endswith('.encrypted')]
    backup_files.sort(reverse=True)  # Most recent first
    
    if len(backup_files) > keep_count:
        for old_backup in backup_files[keep_count:]:
            backup_path = os.path.join(backup_dir, old_backup)
            os.remove(backup_path)
            print(f"Removed old backup: {old_backup}")

def main():
    """Main backup script interface"""
    print("VaultGuard Backup Utility")
    print("1. Create backup")
    print("2. Restore backup")
    print("3. Cleanup old backups")
    
    choice = input("Choose option (1-3): ").strip()
    
    if choice == '1':
        create_backup()
        cleanup_old_backups()
    elif choice == '2':
        backup_dir = 'backups'
        if os.path.exists(backup_dir):
            backups = [f for f in os.listdir(backup_dir) if f.endswith('.encrypted')]
            if backups:
                print("Available backups:")
                for i, backup in enumerate(sorted(backups, reverse=True)):
                    print(f"{i+1}. {backup}")
                
                try:
                    selection = int(input("Select backup number: ")) - 1
                    backup_path = os.path.join(backup_dir, sorted(backups, reverse=True)[selection])
                    backup_password = input("Enter backup password: ")
                    restore_backup(backup_path, backup_password)
                except (ValueError, IndexError):
                    print("Invalid selection")
            else:
                print("No backups found")
        else:
            print("No backup directory found")
    elif choice == '3':
        cleanup_old_backups()
    else:
        print("Invalid choice")

if __name__ == '__main__':
    main()