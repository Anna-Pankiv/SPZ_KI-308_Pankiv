import schedule
import time
import threading
import logging

# Налаштування логування
logging.basicConfig(filename='backup.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PythonScheduler:
    # Ініціалізація планувальника резервного копіювання
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.schedule_thread = None
        self.running = False
        self.schedule = None

    # Перевірка, чи активне завдання планування
    def is_task_enabled(self):
        return self.running

    # Отримання статусу завдання планування
    def get_task_status(self):
        if self.running:
            return "Running", time.strftime('%Y-%m-%d %H:%M:%S'), 0
        return "Not running", None, None

    # Планування резервного копіювання з вказаною частотою
    def schedule_backup(self, frequency='daily'):
        try:
            self.stop()
            self.schedule = schedule.every()
            if frequency == 'daily':
                self.schedule.days.at("00:00").do(self.run_backup).tag('backup_task')
            elif frequency == 'weekly':
                self.schedule.weeks.at("00:00").do(self.run_backup).tag('backup_task')
            elif frequency == 'monthly':
                self.schedule.months.at("00:00").do(self.run_backup).tag('backup_task')
            self.running = True
            self.start_schedule_thread()
            self.backup_manager.config['schedule'] = frequency
            self.backup_manager.save_config()
            logging.info(f"Scheduled {frequency} backup")
            return True
        except Exception as e:
            logging.error(f"Failed to schedule backup: {str(e)}")  # Критична помилка: не вдалося запланувати резервне копіювання
            return False

    # Виконання резервного копіювання за розкладом
    def run_backup(self):
        logging.info("Starting scheduled backup")
        success = self.backup_manager.create_backup(is_scheduled=True)
        if success:
            logging.info("Scheduled backup completed successfully")
        else:
            logging.error("Scheduled backup failed")  # Критична помилка: заплановане резервне копіювання не вдалося
        return success

    # Запуск потоку для планування
    def start_schedule_thread(self):
        if not self.schedule_thread or not self.schedule_thread.is_alive():
            self.running = True
            self.schedule_thread = threading.Thread(target=self.run_schedule_loop, daemon=True)
            self.schedule_thread.start()
            logging.info("Scheduler thread started")

    # Цикл виконання запланованих завдань
    def run_schedule_loop(self):
        while self.running:
            schedule.run_pending()
            time.sleep(60)

    # Зупинка планування
    def stop(self):
        if self.running:
            self.running = False
            schedule.clear('backup_task')
            if self.schedule_thread:
                self.schedule_thread.join(timeout=5)  # Чекаємо завершення потоку з таймаутом
            logging.info("Scheduled backup stopped")
