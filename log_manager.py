import logging

# Налаштування логування
logging.basicConfig(filename='backup.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class LogManager:
    # Отримання вмісту логів
    def get_logs(self):
        try:
            with open('backup.log', 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Failed to read logs: {str(e)}")  # Критична помилка: не вдалося прочитати логи
            return ""

    # Експорт логів у файл
    def export_report(self, output_path):
        try:
            with open('backup.log', 'r', encoding='utf-8') as f:
                logs = f.read()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(logs)
            logging.info(f"Report exported to {output_path}")
        except Exception as e:
            logging.error(f"Failed to export report: {str(e)}")  # Критична помилка: не вдалося експортувати звіт
