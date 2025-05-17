import os
import shutil
import zipfile
import hashlib
import logging
import json
import re
from datetime import datetime, timedelta
import secrets
import tempfile

class BackupManager:
    def __init__(self, backup_dir, encryptor):
        self.backup_dir = os.path.normpath(backup_dir)
        self.encryptor = encryptor
        os.makedirs(self.backup_dir, exist_ok=True)
        self.config_file = os.path.join(self.backup_dir, 'backup_config.json')
        self.checksums_file = os.path.join(self.backup_dir, 'checksums.json')
        self.load_config()
        self.load_checksums()

    def load_config(self):
        self.config = {
            'paths': [],
            'scheduled_paths': [],
            'schedule': 'daily',
            'max_backups': 5,
            'retention_period': '1_month',
            'days_to_keep': 30,
            'language': 'uk',
            'scheduled_password': None
        }
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config.update(json.load(f))
            except Exception as e:
                logging.error(f"Failed to load config: {str(e)}")

    def save_config(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Failed to save config: {str(e)}")

    def load_checksums(self):
        self.checksums = {}
        if os.path.exists(self.checksums_file):
            try:
                with open(self.checksums_file, 'r', encoding='utf-8') as f:
                    self.checksums = json.load(f)
            except Exception as e:
                logging.error(f"Failed to load checksums: {str(e)}")

    def save_checksums(self):
        try:
            with open(self.checksums_file, 'w', encoding='utf-8') as f:
                json.dump(self.checksums, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Failed to save checksums: {str(e)}")

    def is_backup_encrypted(self, backup_name):
        backup_path = os.path.join(self.backup_dir, backup_name)
        try:
            with zipfile.ZipFile(backup_path, 'r') as zf:
                return "salt.bin" in zf.namelist()
        except Exception as e:
            logging.error(f"Failed to check backup encryption: {str(e)}")
            return False

    def create_backup(self, paths=None, password=None, is_scheduled=False):
        if is_scheduled:
            paths = self.config['scheduled_paths']
            password = self.config.get('scheduled_password')
        else:
            paths = paths or self.config['paths']
        
        if not paths:
            logging.error("No paths selected for backup")
            return False

        from .cleaner import Cleaner
        cleaner = Cleaner(self)
        if not cleaner.check_disk_space(1024 * 1024 * 100):  # Require 100MB free
            logging.error("Insufficient disk space for backup")
            return False

        salt = None
        if password:
            salt = secrets.token_bytes(16)
            self.encryptor.derive_key(password, salt)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"backup_{timestamp}.zip"
        backup_path = os.path.join(self.backup_dir, backup_name)
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                if salt:
                    with tempfile.NamedTemporaryFile(delete=False) as salt_file:
                        salt_file.write(salt)
                        salt_path = salt_file.name
                    zf.write(salt_path, "salt.bin")
                    os.remove(salt_path)
                
                for path in paths:
                    path = os.path.normpath(path)
                    if not os.path.exists(path):
                        logging.warning(f"Path does not exist: {path}")
                        continue
                    if os.path.isfile(path):
                        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                            temp_path = temp_file.name
                        self.encryptor.encrypt_file(path, temp_path)
                        zf.write(temp_path, os.path.basename(path))
                        os.remove(temp_path)
                    elif os.path.isdir(path):
                        for root, _, files in os.walk(path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                rel_path = os.path.relpath(file_path, os.path.dirname(path))
                                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                                    temp_path = temp_file.name
                                self.encryptor.encrypt_file(file_path, temp_path)
                                zf.write(temp_path, rel_path)
                                os.remove(temp_path)
            checksum = self.calculate_checksum(backup_path)
            self.checksums[backup_name] = checksum
            self.save_checksums()
            logging.info(f"Backup created: {backup_name}, Checksum: {checksum}")
            self.clean_old_backups()
            return True
        except Exception as e:
            logging.error(f"Backup failed: {str(e)}")
            return False

    def restore_backup(self, backup_name, restore_dir, password=None):
        backup_path = os.path.join(self.backup_dir, backup_name)
        
        if not self.verify_checksum(backup_path):
            logging.error("Backup integrity check failed")
            return False
        
        try:
            os.makedirs(restore_dir, exist_ok=True)
            with zipfile.ZipFile(backup_path, 'r') as zf:
                salt = None
                is_encrypted = "salt.bin" in zf.namelist()
                if is_encrypted:
                    if not password:
                        logging.error("Password required for encrypted backup")
                        return False
                    zf.extract("salt.bin", path=restore_dir)
                    salt_path = os.path.join(restore_dir, "salt.bin")
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
                    os.remove(salt_path)
                    self.encryptor.derive_key(password, salt)
                
                for file_info in zf.infolist():
                    if file_info.filename == "salt.bin":
                        continue
                    zf.extract(file_info, restore_dir)
                    extracted_path = os.path.join(restore_dir, file_info.filename)
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_path = temp_file.name
                    self.encryptor.decrypt_file(extracted_path, temp_path)
                    shutil.move(temp_path, extracted_path)
            logging.info(f"Restored backup: {backup_name} to {restore_dir}")
            return True
        except Exception as e:
            logging.error(f"Restore failed: {str(e)}")
            return False

    def calculate_checksum(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def verify_checksum(self, file_path):
        backup_name = os.path.basename(file_path)
        if backup_name not in self.checksums:
            logging.error(f"No checksum found for {backup_name}")
            return False
        current_checksum = self.calculate_checksum(file_path)
        stored_checksum = self.checksums[backup_name]
        is_valid = current_checksum == stored_checksum
        if not is_valid:
            logging.error(f"Checksum mismatch for {backup_name}: expected {stored_checksum}, got {current_checksum}")
        return is_valid

    def clean_old_backups(self):
        backups = sorted(
            [f for f in os.listdir(self.backup_dir) if f.endswith('.zip')],
            key=lambda name: os.path.getmtime(os.path.join(self.backup_dir, name))
        )
        max_backups = self.config.get('max_backups', 5)

        retention_period = self.config.get('retention_period', '1_month')
        days_to_keep = {
            '1_day': 1,
            '1_week': 7,
            '1_month': 30,
            'custom': self.config.get('days_to_keep', 30)
        }.get(retention_period, 30)

        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        backups_to_keep = backups[-max_backups:]  # Keep the last max_backups

        for backup in backups:
            if backup in backups_to_keep:
                continue

            match = re.search(r'(\d{8})', backup)  # Look for date in YYYYMMDD format
            if match:
                try:
                    file_date = datetime.strptime(match.group(1), '%Y%m%d')
                    logging.info(f"Checking backup {backup}: date={file_date.date()}, cutoff={cutoff_date.date()}")
                    if file_date < cutoff_date:
                        backup_path = os.path.join(self.backup_dir, backup)
                        os.remove(backup_path)
                        self.checksums.pop(backup, None)
                        self.save_checksums()
                        logging.info(f"Deleted old backup: {backup}")
                except Exception as e:
                    logging.error(f"Failed to parse or delete backup {backup}: {str(e)}")
            else:
                logging.warning(f"No date found in backup name: {backup}")
