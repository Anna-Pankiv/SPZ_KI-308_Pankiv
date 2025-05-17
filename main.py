import os
import logging
from src.core.encryptor import Encryptor
from src.core.backup_manager import BackupManager
from src.core.scheduler import PythonScheduler
from src.core.log_manager import LogManager
from src.ui.ui_manager import UIManager

# Налаштування логування
logging.basicConfig(
    filename='backup.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

if __name__ == "__main__":
    # Ініціалізація компонентів
    backup_dir = os.path.join(os.path.dirname(__file__), "backups")
    encryptor = Encryptor()
    backup_manager = BackupManager(backup_dir=backup_dir, encryptor=encryptor)
    scheduler = PythonScheduler(backup_manager)
    log_manager = LogManager()

    # Запуск UI
    ui = UIManager(backup_manager, scheduler, log_manager)
    ui.run()
