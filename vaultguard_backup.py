#!/usr/bin/env python3
"""
Enhanced VaultGuard Database Backup & Restore System
Creates encrypted backups with integrity checking and metadata
"""
import os
import sqlite3
import json
import zipfile
import shutil
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import secrets

def generate_backup_key(master_password):
    """Generate encryption key for backup using PBKDF2"""
    salt = b'vaultguard_backup_salt_2024_enhanced'
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of file for integrity verification"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None

def get_database_stats(db_path):
    """Get database statistics for backup metadata"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Get table counts
        cursor.execute("SELECT COUNT(*) FROM user")
        stats['user_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vault_entry")
        stats['vault_count'] = cursor.fetchone()[0]
        
        # Get database size
        stats['db_size'] = os.path.getsize(db_path)
        
        # Check for additional tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        stats['tables'] = tables
        
        conn.close()
        return stats
        
    except Exception as e:
        print(f"Warning: Could not get database stats: {e}")
        return {}

def create_backup(db_path='vaultguard_secure.db', backup_password=None, backup_dir='backups'):
    """Create encrypted database backup with enhanced features"""
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found!")
        return False
    
    if not backup_password:
        backup_password = input("Enter backup encryption password: ")
    
    # Validate password strength
    if len(backup_password) < 8:
        print("Backup password must be at least 8 characters long!")
        return False
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(backup_dir, exist_ok=True)
    
    # Get database statistics
    db_stats = get_database_stats(db_path)
    
    # Calculate original database hash
    original_hash = calculate_file_hash(db_path)
    
    # Create backup metadata
    backup_info = {
        'timestamp': timestamp,
        'database_file': db_path,
        'backup_version': '2.0',
        'encrypted': True,
        'original_hash': original_hash,
        'backup_id': secrets.token_hex(16),
        'database_stats': db_stats,
        'backup_size': 0,  # Will be filled later
        'compression_ratio': 0.0  # Will be calculated
    }
    
    try:
        print(f"Creating backup for database with {db_stats.get('user_count', 0)} users and {db_stats.get('vault_count', 0)} passwords...")
        
        # Copy database to temp location
        temp_db = f"temp_backup_{timestamp}.db"
        shutil.copy2(db_path, temp_db)
        
        # Verify the copy
        temp_hash = calculate_file_hash(temp_db)
        if temp_hash != original_hash:
            print("Error: Backup copy verification failed!")
            os.remove(temp_db)
            return False
        
        # Create ZIP archive with compression
        backup_zip = f"{backup_dir}/vaultguard_backup_{timestamp}.zip"
        with zipfile.ZipFile(backup_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.write(temp_db, 'database.db')
            zf.writestr('backup_info.json', json.dumps(backup_info, indent=2))
            
            # Add schema backup
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
            schema_sql = [row[0] for row in cursor.fetchall() if row[0]]
            conn.close()
            
            zf.writestr('schema.sql', '\n\n'.join(schema_sql))
        
        # Calculate compression ratio
        original_size = os.path.getsize(temp_db)
        compressed_size = os.path.getsize(backup_zip)
        compression_ratio = (original_size - compressed_size) / original_size * 100
        backup_info['compression_ratio'] = compression_ratio
        backup_info['backup_size'] = compressed_size
        
        # Update backup info with final stats
        with zipfile.ZipFile(backup_zip, 'a') as zf:
            zf.writestr('backup_info.json', json.dumps(backup_info, indent=2))
        
        # Encrypt the backup
        backup_key = generate_backup_key(backup_password)
        fernet = Fernet(backup_key)
        
        with open(backup_zip, 'rb') as f:
            backup_data = f.read()
        
        encrypted_backup = fernet.encrypt(backup_data)
        encrypted_backup_path = f"{backup_dir}/vaultguard_backup_{timestamp}.vgb"  # VaultGuard Backup format
        
        with open(encrypted_backup_path, 'wb') as f:
            f.write(encrypted_backup)
        
        # Create backup manifest
        manifest = {
            'backup_id': backup_info['backup_id'],
            'timestamp': timestamp,
            'encrypted_file': os.path.basename(encrypted_backup_path),
            'original_db': db_path,
            'file_hash': calculate_file_hash(encrypted_backup_path),
            'user_count': db_stats.get('user_count', 0),
            'vault_count': db_stats.get('vault_count', 0),
            'compression_ratio': compression_ratio
        }
        
        manifest_path = f"{backup_dir}/backup_manifest_{timestamp}.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Cleanup temp files
        os.remove(temp_db)
        os.remove(backup_zip)
        
        print(f"\n✅ Encrypted backup created successfully!")
        print(f"   📁 Backup file: {encrypted_backup_path}")
        print(f"   📋 Manifest: {manifest_path}")
        print(f"   📊 Users: {db_stats.get('user_count', 0)}, Passwords: {db_stats.get('vault_count', 0)}")
        print(f"   💾 Size: {compressed_size:,} bytes (compression: {compression_ratio:.1f}%)")
        print(f"   🔐 Backup ID: {backup_info['backup_id']}")
        
        return True
        
    except Exception as e:
        print(f"Backup failed: {e}")
        # Cleanup on failure
        for temp_file in [temp_db, backup_zip]:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        return False

def restore_backup(backup_path, backup_password, restore_path='vaultguard_restored.db'):
    """Restore database from encrypted backup with verification"""
    if not os.path.exists(backup_path):
        print(f"Backup file {backup_path} not found!")
        return False
    
    if not backup_password:
        backup_password = input("Enter backup decryption password: ")
    
    try:
        print(f"Restoring backup from: {backup_path}")
        
        # Decrypt backup
        backup_key = generate_backup_key(backup_password)
        fernet = Fernet(backup_key)
        
        with open(backup_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except Exception:
            print("❌ Invalid backup password or corrupted backup file!")
            return False
        
        # Extract ZIP
        temp_zip = 'temp_restore.zip'
        with open(temp_zip, 'wb') as f:
            f.write(decrypted_data)
        
        with zipfile.ZipFile(temp_zip, 'r') as zf:
            # Read and display backup info
            backup_info = json.loads(zf.read('backup_info.json'))
            
            print(f"\n📋 Backup Information:")
            print(f"   🕒 Created: {backup_info['timestamp']}")
            print(f"   🆔 Backup ID: {backup_info['backup_id']}")
            print(f"   📊 Users: {backup_info['database_stats'].get('user_count', 'Unknown')}")
            print(f"   🔑 Passwords: {backup_info['database_stats'].get('vault_count', 'Unknown')}")
            print(f"   💾 Original Size: {backup_info['database_stats'].get('db_size', 0):,} bytes")
            
            # Confirm restoration
            confirm = input(f"\nRestore this backup to {restore_path}? (y/n): ").lower().strip()
            if confirm != 'y':
                print("❌ Restoration cancelled")
                os.remove(temp_zip)
                return False
            
            # Extract database
            zf.extract('database.db', '.')
            shutil.move('database.db', restore_path)
            
            # Verify restored database
            if backup_info.get('original_hash'):
                restored_hash = calculate_file_hash(restore_path)
                if restored_hash == backup_info['original_hash']:
                    print("✅ Database integrity verified!")
                else:
                    print("⚠️  Warning: Database integrity check failed!")
        
        # Cleanup
        os.remove(temp_zip)
        
        # Test the restored database
        try:
            conn = sqlite3.connect(restore_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM user")
            user_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM vault_entry")
            vault_count = cursor.fetchone()[0]
            conn.close()
            
            print(f"\n🎉 Database restored successfully!")
            print(f"   📁 Restored to: {restore_path}")
            print(f"   📊 Verified: {user_count} users, {vault_count} passwords")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not verify restored database: {e}")
        
        return True
        
    except Exception as e:
        print(f"Restore failed: {e}")
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return False

def list_backups(backup_dir='backups'):
    """List all available backups with detailed information"""
    if not os.path.exists(backup_dir):
        print("No backup directory found")
        return []
    
    # Find all backup files (.vgb extension) and manifests
    backup_files = []
    manifest_files = {}
    
    for file in os.listdir(backup_dir):
        if file.endswith('.vgb'):
            backup_files.append(file)
        elif file.startswith('backup_manifest_') and file.endswith('.json'):
            timestamp = file.replace('backup_manifest_', '').replace('.json', '')
            manifest_files[timestamp] = file
    
    if not backup_files:
        print("No backups found in directory")
        return []
    
    backup_info = []
    
    print(f"\n📋 Available Backups (in {backup_dir}):")
    print("-" * 80)
    print(f"{'#':<2} | {'Timestamp':<15} | {'Users':<6} | {'Passwords':<9} | {'Size':<10} | {'Backup ID'[:12]:<12}")
    print("-" * 80)
    
    for i, backup_file in enumerate(sorted(backup_files, reverse=True), 1):
        try:
            # Extract timestamp from filename
            timestamp = backup_file.replace('vaultguard_backup_', '').replace('.vgb', '')
            
            # Get file size
            file_path = os.path.join(backup_dir, backup_file)
            file_size = os.path.getsize(file_path)
            size_str = format_size(file_size)
            
            # Try to get info from manifest
            users = "?"
            passwords = "?"
            backup_id = "Unknown"
            
            if timestamp in manifest_files:
                manifest_path = os.path.join(backup_dir, manifest_files[timestamp])
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                    users = str(manifest.get('user_count', '?'))
                    passwords = str(manifest.get('vault_count', '?'))
                    backup_id = manifest.get('backup_id', 'Unknown')[:12]
            
            print(f"{i:<2} | {timestamp:<15} | {users:<6} | {passwords:<9} | {size_str:<10} | {backup_id}")
            
            backup_info.append({
                'index': i,
                'file': backup_file,
                'path': file_path,
                'timestamp': timestamp,
                'size': file_size
            })
            
        except Exception as e:
            print(f"Error reading backup {backup_file}: {e}")
    
    return backup_info

def format_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f}KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/1024**2:.1f}MB"
    else:
        return f"{size_bytes/1024**3:.1f}GB"

def cleanup_old_backups(backup_dir='backups', keep_count=10):
    """Remove old backup files, keeping only the most recent ones"""
    if not os.path.exists(backup_dir):
        print("No backup directory found")
        return
    
    # Get all backup files
    backup_files = [f for f in os.listdir(backup_dir) if f.endswith('.vgb')]
    manifest_files = [f for f in os.listdir(backup_dir) if f.startswith('backup_manifest_')]
    
    if len(backup_files) <= keep_count:
        print(f"Only {len(backup_files)} backups found, no cleanup needed")
        return
    
    # Sort by timestamp (newest first)
    backup_files.sort(key=lambda x: x.replace('vaultguard_backup_', '').replace('.vgb', ''), reverse=True)
    
    old_backups = backup_files[keep_count:]
    
    if not old_backups:
        print("No old backups to clean up")
        return
    
    print(f"Found {len(old_backups)} old backups to remove:")
    total_size = 0
    
    for backup in old_backups:
        backup_path = os.path.join(backup_dir, backup)
        size = os.path.getsize(backup_path)
        total_size += size
        
        timestamp = backup.replace('vaultguard_backup_', '').replace('.vgb', '')
        print(f"  - {backup} ({format_size(size)})")
        
        # Remove corresponding manifest
        manifest_file = f"backup_manifest_{timestamp}.json"
        manifest_path = os.path.join(backup_dir, manifest_file)
        
        os.remove(backup_path)
        if os.path.exists(manifest_path):
            os.remove(manifest_path)
    
    print(f"\n🧹 Cleaned up {len(old_backups)} old backups ({format_size(total_size)} freed)")

def verify_backup_integrity(backup_path, backup_password):
    """Verify backup file integrity without full restoration"""
    try:
        print(f"Verifying backup: {backup_path}")
        
        # Decrypt backup
        backup_key = generate_backup_key(backup_password)
        fernet = Fernet(backup_key)
        
        with open(backup_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except Exception:
            print("❌ Invalid password or corrupted backup!")
            return False
        
        # Test ZIP extraction
        temp_zip = 'temp_verify.zip'
        with open(temp_zip, 'wb') as f:
            f.write(decrypted_data)
        
        with zipfile.ZipFile(temp_zip, 'r') as zf:
            # Check required files
            required_files = ['database.db', 'backup_info.json']
            missing_files = []
            
            for req_file in required_files:
                if req_file not in zf.namelist():
                    missing_files.append(req_file)
            
            if missing_files:
                print(f"❌ Backup missing required files: {missing_files}")
                os.remove(temp_zip)
                return False
            
            # Read and validate backup info
            backup_info = json.loads(zf.read('backup_info.json'))
            
            print(f"✅ Backup verification successful!")
            print(f"   🆔 Backup ID: {backup_info.get('backup_id', 'Unknown')}")
            print(f"   🕒 Created: {backup_info.get('timestamp', 'Unknown')}")
            print(f"   📊 Contains: {backup_info.get('database_stats', {}).get('user_count', '?')} users")
        
        os.remove(temp_zip)
        return True
        
    except Exception as e:
        print(f"Verification failed: {e}")
        if os.path.exists('temp_verify.zip'):
            os.remove('temp_verify.zip')
        return False

def main():
    """Enhanced main backup script interface"""
    print("🛡️  VaultGuard Enhanced Backup & Restore System")
    print("=" * 60)
    print("🔐 Features: AES encryption, integrity verification, compression")
    print()
    
    print("1. 💾 Create encrypted backup")
    print("2. 🔄 Restore from backup")
    print("3. 📋 List all backups")
    print("4. 🧹 Cleanup old backups")
    print("5. ✅ Verify backup integrity")
    print("6. ❌ Exit")
    
    while True:
        try:
            choice = input("\nChoose option (1-6): ").strip()
            
            if choice == '1':
                db_path = input("Database file (default: vaultguard_secure.db): ").strip() or 'vaultguard_secure.db'
                if create_backup(db_path):
                    cleanup_old_backups()
                
            elif choice == '2':
                backup_dir = 'backups'
                backups = list_backups(backup_dir)
                
                if not backups:
                    continue
                
                try:
                    selection = int(input(f"\nSelect backup number (1-{len(backups)}): "))
                    if 1 <= selection <= len(backups):
                        selected_backup = backups[selection - 1]
                        backup_password = input("Enter backup password: ")
                        restore_path = input("Restore to (default: vaultguard_restored.db): ").strip()
                        restore_path = restore_path or 'vaultguard_restored.db'
                        
                        restore_backup(selected_backup['path'], backup_password, restore_path)
                    else:
                        print("❌ Invalid selection")
                except ValueError:
                    print("❌ Please enter a valid number")
                
            elif choice == '3':
                list_backups()
                
            elif choice == '4':
                try:
                    keep_count = int(input("How many recent backups to keep? (default: 10): ") or "10")
                    cleanup_old_backups(keep_count=keep_count)
                except ValueError:
                    print("❌ Invalid number")
                
            elif choice == '5':
                backup_dir = 'backups'
                backups = list_backups(backup_dir)
                
                if not backups:
                    continue
                
                try:
                    selection = int(input(f"\nSelect backup to verify (1-{len(backups)}): "))
                    if 1 <= selection <= len(backups):
                        selected_backup = backups[selection - 1]
                        backup_password = input("Enter backup password: ")
                        verify_backup_integrity(selected_backup['path'], backup_password)
                    else:
                        print("❌ Invalid selection")
                except ValueError:
                    print("❌ Please enter a valid number")
                
            elif choice == '6':
                print("👋 Backup system closed")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-6.")
                
        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")

if __name__ == '__main__':
    main()
