import logging
from encryptor import Encryptor
from backup_manager import BackupManager
from scheduler import PythonScheduler
from log_manager import LogManager
from ui_manager import UIManager

# Налаштування логування
logging.basicConfig(filename='backup.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    try:  # Ініціалізація компонентів
        encryptor = Encryptor()
        backup_manager = BackupManager(backup_dir="backups", encryptor=encryptor)
        scheduler = PythonScheduler(backup_manager)
        log_manager = LogManager()
        
        ui = UIManager(backup_manager, scheduler, log_manager)
        ui.run()
    except Exception as e:
        logging.error(f"Application failed to start: {str(e)}")  # Критична помилка: програма не запустилася
        raise
