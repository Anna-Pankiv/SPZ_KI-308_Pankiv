import os
import shutil
import zipfile
import hashlib
import json
import logging
import secrets
import tempfile
import re
from datetime import datetime, timedelta

# Налаштування логування
logging.basicConfig(filename='backup.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class BackupManager:
    # Ініціалізація менеджера резервного копіювання з директорією та об'єктом шифрування
    def __init__(self, backup_dir, encryptor):
        self.backup_dir = os.path.normpath(backup_dir)
        self.encryptor = encryptor
        try:
            os.makedirs(self.backup_dir, exist_ok=True)  # Створюємо директорію, якщо вона не існує
        except Exception as e:
            logging.error(f"Failed to create backup directory {self.backup_dir}: {str(e)}")  # Критична помилка: не вдалося створити директорію
            raise
        self.config_file = os.path.join(self.backup_dir, 'backup_config.json')
        self.checksums_file = os.path.join(self.backup_dir, 'checksums.json')
        self.load_config()
        self.load_checksums()

    # Завантаження конфігурації з файлу
    def load_config(self):
        self.config = {
            'paths': [],
            'scheduled_paths': [],
            'schedule': 'daily',
            'max_backups': 5,
            'retention_period': '1_day',
            'days_to_keep': 1,
            'language': 'uk',
            'scheduled_password': None
        }
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config.update(json.load(f))  # Оновлюємо конфіг із файлу
            except Exception as e:
                logging.error(f"Failed to load config: {str(e)}")  # Критична помилка: не вдалося завантажити конфіг

    # Збереження конфігурації у файл
    def save_config(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Failed to save config: {str(e)}")  # Критична помилка: не вдалося зберегти конфіг

    # Завантаження контрольних сум із файлу
    def load_checksums(self):
        self.checksums = {}
        if os.path.exists(self.checksums_file):
            try:
                with open(self.checksums_file, 'r', encoding='utf-8') as f:
                    self.checksums = json.load(f)  # Завантажуємо контрольні суми
            except Exception as e:
                logging.error(f"Failed to load checksums: {str(e)}")  # Критична помилка: не вдалося завантажити контрольні суми

    # Збереження контрольних сум у файл
    def save_checksums(self):
        try:
            with open(self.checksums_file, 'w', encoding='utf-8') as f:
                json.dump(self.checksums, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Failed to save checksums: {str(e)}")  # Критична помилка: не вдалося зберегти контрольні суми

    # Перевірка, чи є резервна копія зашифрованою
    def is_backup_encrypted(self, backup_name):
        backup_path = os.path.join(self.backup_dir, backup_name)
        try:
            with zipfile.ZipFile(backup_path, 'r') as zf:
                return "salt.bin" in zf.namelist()  # Перевіряємо наявність salt.bin для визначення шифрування
        except Exception as e:
            logging.error(f"Failed to check backup encryption: {str(e)}")  # Помилка: не вдалося перевірити шифрування
            return False

    # Отримання вмісту резервної копії
    def get_backup_contents(self, backup_name):
        backup_path = os.path.join(self.backup_dir, backup_name)
        try:
            with zipfile.ZipFile(backup_path, 'r') as zf:
                contents = [name for name in zf.namelist() if name != "salt.bin"]
                return contents
        except Exception as e:
            logging.error(f"Failed to get backup contents: {str(e)}")  # Помилка: не вдалося отримати вміст резервної копії
            return []

    # Створення резервної копії для вказаних шляхів
    def create_backup(self, paths=None, password=None, is_scheduled=False):
        if is_scheduled:
            paths = self.config['scheduled_paths']
            password = self.config.get('scheduled_password')
        else:
            paths = paths or self.config['paths']
        
        if not paths:
            logging.error("No paths selected for backup")  # Критична помилка: відсутні шляхи для резервного копіювання
            return False

        from cleaner import Cleaner
        cleaner = Cleaner(self)
        if not cleaner.check_disk_space(1024 * 1024 * 100):  # Перевірка наявності 100 МБ вільного місця
            logging.error("Insufficient disk space for backup")  # Критична помилка: недостатньо місця на диску
            return False

        salt = None
        if password:
            salt = secrets.token_bytes(16)  # Генерація випадкового salt для шифрування
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
                    zf.write(salt_path, "salt.bin")  # Додаємо salt до архіву
                    os.remove(salt_path)
                
                for path in paths:
                    path = os.path.normpath(path)
                    if not os.path.exists(path):
                        logging.warning(f"Path does not exist: {path}")  # Попередження: шлях не існує
                        continue
                    if os.path.isfile(path):
                        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                            temp_path = temp_file.name
                        self.encryptor.encrypt_file(path, temp_path)
                        zf.write(temp_path, os.path.basename(path))  # Додаємо файл до архіву
                        os.remove(temp_path)
                    elif os.path.isdir(path):
                        for root, _, files in os.walk(path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                rel_path = os.path.relpath(file_path, os.path.dirname(path))
                                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                                    temp_path = temp_file.name
                                self.encryptor.encrypt_file(file_path, temp_path)
                                zf.write(temp_path, rel_path)  # Додаємо файл із відносним шляхом
                                os.remove(temp_path)
            checksum = self.calculate_checksum(backup_path)
            self.checksums[backup_name] = checksum
            self.save_checksums()
            logging.info(f"Backup created: {backup_name}, Checksum: {checksum}")
            self.clean_old_backups()
            return True
        except Exception as e:
            logging.error(f"Backup failed: {str(e)}")  # Критична помилка: створення резервної копії не вдалося
            return False

    # Відновлення резервної копії у вказану директорію
    def restore_backup(self, backup_name, restore_dir, password=None):
        backup_path = os.path.join(self.backup_dir, backup_name)
        
        if not self.verify_checksum(backup_path):
            logging.error("Backup integrity check failed")  # Критична помилка: контрольна сума не збігається
            return False
        
        try:
            os.makedirs(restore_dir, exist_ok=True)  # Створюємо директорію для відновлення
            with zipfile.ZipFile(backup_path, 'r') as zf:
                salt = None
                is_encrypted = "salt.bin" in zf.namelist()
                if is_encrypted:
                    if not password:
                        logging.error("Password required for encrypted backup")  # Критична помилка: потрібен пароль для зашифрованої копії
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
                    shutil.move(temp_path, extracted_path)  # Переміщаємо розшифрований файл
            logging.info(f"Restored backup: {backup_name} to {restore_dir}")
            return True
        except Exception as e:
            logging.error(f"Restore failed: {str(e)}")  # Критична помилка: відновлення не вдалося
            return False

    # Обчислення контрольної суми файлу
    def calculate_checksum(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)  # Обчислюємо контрольну суму частинами для ефективності
        return sha256.hexdigest()

    # Перевірка цілісності файлу за контрольною сумою
    def verify_checksum(self, file_path):
        backup_name = os.path.basename(file_path)
        if backup_name not in self.checksums:
            logging.error(f"No checksum found for {backup_name}")  # Критична помилка: відсутня контрольна сума
            return False
        current_checksum = self.calculate_checksum(file_path)
        stored_checksum = self.checksums[backup_name]
        is_valid = current_checksum == stored_checksum
        if not is_valid:
            logging.error(f"Checksum mismatch for {backup_name}: expected {stored_checksum}, got {current_checksum}")  # Критична помилка: невідповідність контрольної суми
        return is_valid

    # Видалення старих резервних копій на основі політики зберігання
    def clean_old_backups(self):
        backups = sorted(
            [f for f in os.listdir(self.backup_dir) if f.endswith('.zip')],
            key=lambda name: os.path.getmtime(os.path.join(self.backup_dir, name))
        )
        max_backups = self.config.get('max_backups', 5)
        retention_period = self.config.get('retention_period', '1_day')
        
        days_to_keep = self.config.get('days_to_keep', 1)
        if retention_period == '1_week':
            days_to_keep = 7
        elif retention_period == '1_month':
            days_to_keep = 30
        elif retention_period == 'custom':
            days_to_keep = max(1, self.config.get('days_to_keep', 1))

        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        backups_to_keep = backups[-max_backups:]

        for backup in backups:
            if backup in backups_to_keep:
                continue

            match = re.search(r'(\d{8})', backup)
            if match:
                try:
                    file_date = datetime.strptime(match.group(1), '%Y%m%d')
                    if file_date < cutoff_date:
                        backup_path = os.path.join(self.backup_dir, backup)
                        os.remove(backup_path)  # Видаляємо старий файл резервної копії
                        self.checksums.pop(backup, None)
                        self.save_checksums()
                        logging.info(f"Deleted old backup: {backup}")
                except Exception as e:
                    logging.error(f"Failed to parse or delete backup {backup}: {str(e)}")  # Помилка: не вдалося видалити або розібрати ім'я файлу
            else:
                logging.warning(f"No date found in backup name: {backup}")  # Попередження: дата не знайдена в імені файлу

    # Отримання вільного місця на диску в мегабайтах
    def get_disk_space(self):
        total, used, free = shutil.disk_usage(self.backup_dir)
        return free // (1024 * 1024)
