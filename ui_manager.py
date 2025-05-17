import os
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import logging

class UIManager:
    def __init__(self):
        # Налаштування CustomTkinter
        ctk.set_appearance_mode("dark")  # Темна тема
        ctk.set_default_color_theme("blue")  # Основний колір (акцент)

        self.root = ctk.CTk()  # Використовуємо CTk замість Tk
        self.root.title("Backup Software")
        backup_dir = os.path.join(os.path.dirname(__file__), "backups")
        self.backup_manager = BackupManager(backup_dir=backup_dir, encryptor=Encryptor())
        self.scheduler = PythonScheduler(self.backup_manager)
        self.log_manager = LogManager()

        # Словник перекладів
        self.translations = {
            'en': {
                'title': 'Backup Software',
                'create_backup': 'Create Backup',
                'restore_backup': 'Restore Backup',
                'files_folders': 'Files/Folders to Backup',
                'add_path': 'Add Path',
                'remove_path': 'Remove Path',
                'password': 'Password (optional, min 8 chars)',
                'select_backup': 'Select Backup',
                'schedule_backup': 'Schedule Backup',
                'daily': 'Daily',
                'weekly': 'Weekly',
                'monthly': 'Monthly',
                'enable_schedule': 'Enable Background Schedule',
                'disable_schedule': 'Disable Background Schedule',
                'schedule_status': 'Background Schedule: {status}',
                'enabled': 'Enabled',
                'disabled': 'Disabled',
                'logs_reports': 'Logs & Reports',
                'view_logs': 'View Logs',
                'export_report': 'Export Report',
                'settings': 'Settings',
                'language': 'Language',
                'retention_period': 'Backup Retention Period',
                '1_day': '1 Day',
                '1_week': '1 Week',
                '1_month': '1 Month',
                'custom': 'Custom',
                'ready': 'Ready',
                'added_path': 'Added path: {path}',
                'removed_path': 'Removed path: {path}',
                'no_path_selected': 'Select a path to remove',
                'backup_success': 'Backup created successfully',
                'backup_failed': 'Backup creation failed',
                'no_backup_selected': 'Select a backup to restore',
                'restore_cancelled': 'Restore cancelled',
                'restore_success': 'Backup restored successfully',
                'restore_failed': 'Restore failed',
                'schedule_started': 'Background schedule enabled: {freq}',
                'schedule_stopped': 'Background schedule disabled',
                'schedule_failed': 'Failed to enable background schedule',
                'viewing_logs': 'Viewing logs',
                'report_exported': 'Report exported to {path}',
                'report_cancelled': 'Report export cancelled',
                'weak_password': 'Password must be at least 8 characters long',
                'enter_restore_password': 'Enter password for restoring backup (min 8 chars)',
                'password_required': 'This backup is encrypted. Please provide a password.',
                'invalid_password': 'Invalid password or decryption failed',
                'schedule_dialog_title': 'Configure Background Schedule',
                'schedule_paths': 'Files/Folders for Scheduled Backup',
                'schedule_password': 'Password for Scheduled Backup (optional, min 8 chars)',
                'confirm': 'Confirm',
                'cancel': 'Cancel',
                'no_paths_for_schedule': 'Please select at least one file or folder for scheduled backup',
                'check_integrity': 'Check Integrity',
                'backup_valid': 'Backup {name} is valid',
                'backup_corrupted': 'Backup {name} is corrupted or checksum missing',
                'integrity_check_failed': 'Failed to check integrity of {name}',
            },
            'uk': {
                'title': 'Програма резервного копіювання',
                'create_backup': 'Створити резервну копію',
                'restore_backup': 'Відновити резервну копію',
                'files_folders': 'Файли/Папки для резервного копіювання',
                'add_path': 'Додати шлях',
                'remove_path': 'Видалити шлях',
                'password': 'Пароль (необов’язково, мін. 8 символів)',
                'select_backup': 'Виберіть резервну копію',
                'schedule_backup': 'Планувати резервне копіювання',
                'daily': 'Щоденно',
                'weekly': 'Щотижня',
                'monthly': 'Щомісяця',
                'enable_schedule': 'Увімкнути фоновий розклад',
                'disable_schedule': 'Вимкнути фоновий розклад',
                'schedule_status': 'Фоновий розклад: {status}',
                'enabled': 'Увімкнено',
                'disabled': 'Вимкнено',
                'logs_reports': 'Журнали та звіти',
                'view_logs': 'Переглянути журнали',
                'export_report': 'Експортувати звіт',
                'settings': 'Налаштування',
                'language': 'Мова',
                'retention_period': 'Період зберігання резервних копій',
                '1_day': '1 день',
                '1_week': '1 тиждень',
                '1_month': '1 місяць',
                'custom': 'Користувацький',
                'ready': 'Готово',
                'added_path': 'Додано шлях: {path}',
                'removed_path': 'Видалено шлях: {path}',
                'no_path_selected': 'Виберіть шлях для видалення',
                'backup_success': 'Резервну копію успішно створено',
                'backup_failed': 'Не вдалося створити резервну копію',
                'no_backup_selected': 'Виберіть резервну копію для відновлення',
                'restore_cancelled': 'Відновлення скасовано',
                'restore_success': 'Резервну копію успішно відновлено',
                'restore_failed': 'Не вдалося відновити резервну копію',
                'schedule_started': 'Фоновий розклад увімкнено: {freq}',
                'schedule_stopped': 'Фоновий розклад вимкнено',
                'schedule_failed': 'Не вдалося увімкнути фоновий розклад',
                'viewing_logs': 'Перегляд журналів',
                'report_exported': 'Звіт експортовано до {path}',
                'report_cancelled': 'Експорт звіту скасовано',
                'weak_password': 'Пароль повинен містити принаймні 8 символів',
                'enter_restore_password': 'Введіть пароль для відновлення резервної копії (мін. 8 символів)',
                'password_required': 'Ця резервна копія зашифрована. Будь ласка, введіть пароль.',
                'invalid_password': 'Невірний пароль або не вдалося розшифрувати',
                'schedule_dialog_title': 'Налаштування фонового розкладу',
                'schedule_paths': 'Файли/Папки для планового резервного копіювання',
                'schedule_password': 'Пароль для планового резервного копіювання (необов’язково, мін. 8 символів)',
                'confirm': 'Підтвердити',
                'cancel': 'Скасувати',
                'no_paths_for_schedule': 'Будь ласка, виберіть принаймні один файл або папку для планового резервного копіювання',
                'check_integrity': 'Перевірити цілісність',
                'backup_valid': 'Резервна копія {name} є валідною',
                'backup_corrupted': 'Резервна копія {name} пошкоджена або відсутня контрольна сума',
                'integrity_check_failed': 'Не вдалося перевірити цілісність {name}',
            }
        }

        # Ініціалізація мови з конфігурації
        self.language = self.backup_manager.config.get('language', 'uk')

        # Налаштування розміру вікна
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Встановлення кастомної іконки
        try:
            if os.path.exists("backup_icon.ico"):
                self.root.iconbitmap("backup_icon.ico")
            elif os.path.exists("backup_icon.png"):
                icon = tk.PhotoImage(file="backup_icon.png")
                self.root.iconphoto(True, icon)
        except Exception as e:
            logging.warning(f"Failed to set icon: {str(e)}")

        self.setup_gui()

    def update_language(self, lang):
        self.language = lang
        self.backup_manager.config['language'] = lang
        self.backup_manager.save_config()
        self.setup_gui()

    def setup_gui(self):
        # Очищення попередніх віджетів
        for widget in self.root.winfo_children():
            widget.destroy()

        # Кольорова палітра
        accent_color = "#007ACC"  # Колір акценту
        padding = 15

        # Основний прокручуваний фрейм
        main_frame = ctk.CTkScrollableFrame(self.root, fg_color="#1E1E1E")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Секція налаштувань
        settings_frame = ctk.CTkFrame(main_frame, fg_color="#2D2D2D")
        settings_frame.pack(fill="x", padx=padding, pady=5)

        settings_label = ctk.CTkLabel(settings_frame, text=self.translations[self.language]['settings'], font=("Arial", 16, "bold"))
        settings_label.pack(anchor="w", padx=padding, pady=5)

        language_frame = ctk.CTkFrame(settings_frame, fg_color="#2D2D2D")
        language_frame.pack(fill="x", padx=padding)

        language_label = ctk.CTkLabel(language_frame, text=self.translations[self.language]['language'], font=("Arial", 14))
        language_label.pack(side="left")

        language_combobox = ctk.CTkComboBox(
            language_frame,
            values=['Українська (uk)', 'English (en)'],
            command=lambda value: self.update_language('uk' if value == 'Українська (uk)' else 'en'),
            width=200,
            font=("Arial", 12)
        )
        language_combobox.set('Українська (uk)' if self.language == 'uk' else 'English (en)')
        language_combobox.pack(side="left", padx=10)

        retention_frame = ctk.CTkFrame(settings_frame, fg_color="#2D2D2D")
        retention_frame.pack(fill="x", padx=padding, pady=5)

        retention_label = ctk.CTkLabel(retention_frame, text=self.translations[self.language]['retention_period'], font=("Arial", 14))
        retention_label.pack(side="left")

        retention_map = {
            self.translations[self.language]['1_day']: '1_day',
            self.translations[self.language]['1_week']: '1_week',
            self.translations[self.language]['1_month']: '1_month',
            self.translations[self.language]['custom']: 'custom'
        }
        retention_combobox = ctk.CTkComboBox(
            retention_frame,
            values=[
                self.translations[self.language]['1_day'],
                self.translations[self.language]['1_week'],
                self.translations[self.language]['1_month'],
                self.translations[self.language]['custom']
            ],
            command=lambda value: self.update_retention(retention_map[value]),
            width=200,
            font=("Arial", 12)
        )
        retention_combobox.set({
            '1_day': self.translations[self.language]['1_day'],
            '1_week': self.translations[self.language]['1_week'],
            '1_month': self.translations[self.language]['1_month'],
            'custom': self.translations[self.language]['custom']
        }.get(self.backup_manager.config['retention_period'], self.translations[self.language]['1_month']))
        retention_combobox.pack(side="left", padx=10)

        # Секція створення резервної копії
        backup_frame = ctk.CTkFrame(main_frame, fg_color="#2D2D2D")
        backup_frame.pack(fill="x", padx=padding, pady=5)

        backup_label = ctk.CTkLabel(backup_frame, text=self.translations[self.language]['create_backup'], font=("Arial", 16, "bold"))
        backup_label.pack(anchor="w", padx=padding, pady=5)

        paths_label = ctk.CTkLabel(backup_frame, text=self.translations[self.language]['files_folders'], font=("Arial", 14))
        paths_label.pack(anchor="w", padx=padding)

        self.paths_listbox = tk.Listbox(backup_frame, width=60, height=6, font=("Arial", 12), bg="#333333", fg="#E0E0E0", selectbackground=accent_color, selectforeground="#FFFFFF", relief="flat", borderwidth=1)
        self.paths_listbox.pack(fill="x", padx=padding, pady=5)
        for path in self.backup_manager.config['paths']:
            self.paths_listbox.insert(tk.END, path)
        for path in self.backup_manager.config['scheduled_paths']:
            self.paths_listbox.insert(tk.END, f"[Scheduled] {path}")

        button_frame = ctk.CTkFrame(backup_frame, fg_color="#2D2D2D")
        button_frame.pack(fill="x", padx=padding, pady=5)

        add_path_button = ctk.CTkButton(button_frame, text=self.translations[self.language]['add_path'], command=self.add_path, font=("Arial", 14))
        add_path_button.pack(side="left", padx=5)

        remove_path_button = ctk.CTkButton(button_frame, text=self.translations[self.language]['remove_path'], command=self.remove_path, font=("Arial", 14))
        remove_path_button.pack(side="left", padx=5)

        password_label = ctk.CTkLabel(backup_frame, text=self.translations[self.language]['password'], font=("Arial", 14))
        password_label.pack(anchor="w", padx=padding, pady=5)

        self.password_entry = ctk.CTkEntry(backup_frame, show="*", width=300, font=("Arial", 12))
        self.password_entry.pack(anchor="w", padx=padding)

        create_backup_button = ctk.CTkButton(backup_frame, text=self.translations[self.language]['create_backup'], command=self.create_backup, font=("Arial", 14))
        create_backup_button.pack(fill="x", padx=padding, pady=10)

        # Секція відновлення
        restore_frame = ctk.CTkFrame(main_frame, fg_color="#2D2D2D")
        restore_frame.pack(fill="x", padx=padding, pady=5)

        restore_label = ctk.CTkLabel(restore_frame, text=self.translations[self.language]['restore_backup'], font=("Arial", 16, "bold"))
        restore_label.pack(anchor="w", padx=padding, pady=5)

        select_backup_label = ctk.CTkLabel(restore_frame, text=self.translations[self.language]['select_backup'], font=("Arial", 14))
        select_backup_label.pack(anchor="w", padx=padding)

        self.backup_combobox = ctk.CTkComboBox(restore_frame, values=self.get_backups(), width=300, font=("Arial", 12))
        self.backup_combobox.pack(anchor="w", padx=padding, pady=5)

        restore_button_frame = ctk.CTkFrame(restore_frame, fg_color="#2D2D2D")
        restore_button_frame.pack(fill="x", padx=padding, pady=5)

        restore_backup_button = ctk.CTkButton(restore_button_frame, text=self.translations[self.language]['restore_backup'], command=self.restore_backup, font=("Arial", 14))
        restore_backup_button.pack(side="left", padx=5)

        check_integrity_button = ctk.CTkButton(restore_button_frame, text=self.translations[self.language]['check_integrity'], command=self.check_integrity, font=("Arial", 14))
        check_integrity_button.pack(side="left", padx=5)

        # Секція планування
        schedule_frame = ctk.CTkFrame(main_frame, fg_color="#2D2D2D")
        schedule_frame.pack(fill="x", padx=padding, pady=5)

        schedule_label = ctk.CTkLabel(schedule_frame, text=self.translations[self.language]['schedule_backup'], font=("Arial", 16, "bold"))
        schedule_label.pack(anchor="w", padx=padding, pady=5)

        self.schedule_var = tk.StringVar(value=self.backup_manager.config.get('schedule', 'daily'))
        daily_radio = ctk.CTkRadioButton(schedule_frame, text=self.translations[self.language]['daily'], variable=self.schedule_var, value="daily", font=("Arial", 14))
        daily_radio.pack(anchor="w", padx=padding)

        weekly_radio = ctk.CTkRadioButton(schedule_frame, text=self.translations[self.language]['weekly'], variable=self.schedule_var, value="weekly", font=("Arial", 14))
        weekly_radio.pack(anchor="w", padx=padding)

        monthly_radio = ctk.CTkRadioButton(schedule_frame, text=self.translations[self.language]['monthly'], variable=self.schedule_var, value="monthly", font=("Arial", 14))
        monthly_radio.pack(anchor="w", padx=padding)

        schedule_button_frame = ctk.CTkFrame(schedule_frame, fg_color="#2D2D2D")
        schedule_button_frame.pack(fill="x", padx=padding, pady=10)

        enable_schedule_button = ctk.CTkButton(schedule_button_frame, text=self.translations[self.language]['enable_schedule'], command=self.start_schedule, font=("Arial", 14))
        enable_schedule_button.pack(side="left", padx=5)

        disable_schedule_button = ctk.CTkButton(schedule_button_frame, text=self.translations[self.language]['disable_schedule'], command=self.stop_schedule, font=("Arial", 14))
        disable_schedule_button.pack(side="left", padx=5)

        # Статус планувальника
        status = self.translations[self.language]['enabled'] if self.scheduler.is_task_enabled() else self.translations[self.language]['disabled']
        self.schedule_status_var = tk.StringVar(value=self.translations[self.language]['schedule_status'].format(status=status))
        schedule_status_label = ctk.CTkLabel(schedule_frame, textvariable=self.schedule_status_var, font=("Arial", 14))
        schedule_status_label.pack(anchor="w", padx=padding, pady=5)

        # Секція логів
        logs_frame = ctk.CTkFrame(main_frame, fg_color="#2D2D2D")
        logs_frame.pack(fill="x", padx=padding, pady=5)

        logs_label = ctk.CTkLabel(logs_frame, text=self.translations[self.language]['logs_reports'], font=("Arial", 16, "bold"))
        logs_label.pack(anchor="w", padx=padding, pady=5)

        logs_button_frame = ctk.CTkFrame(logs_frame, fg_color="#2D2D2D")
        logs_button_frame.pack(fill="x", padx=padding)

        view_logs_button = ctk.CTkButton(logs_button_frame, text=self.translations[self.language]['view_logs'], command=self.view_logs, font=("Arial", 14))
        view_logs_button.pack(side="left", padx=5)

        export_report_button = ctk.CTkButton(logs_button_frame, text=self.translations[self.language]['export_report'], command=self.export_report, font=("Arial", 14))
        export_report_button.pack(side="left", padx=5)

        # Статус-бар
        self.status_var = tk.StringVar(value=self.translations[self.language]['ready'])
        status_bar = ctk.CTkLabel(self.root, textvariable=self.status_var, font=("Arial", 14), fg_color="#252525")
        status_bar.pack(fill="x", padx=10, pady=5)

    def update_retention(self, period):
        self.backup_manager.config['retention_period'] = period
        self.backup_manager.save_config()
        self.backup_manager.clean_old_backups()

    def add_path(self):
        path = filedialog.askopenfilename() or filedialog.askdirectory()
        if path and path not in self.backup_manager.config['paths']:
            path = os.path.normpath(path)
            if not os.path.exists(path):
                messagebox.showerror("Error", f"Path does not exist: {path}")
                return
            self.backup_manager.config['paths'].append(path)
            self.paths_listbox.insert(tk.END, path)
            self.backup_manager.save_config()
            self.status_var.set(self.translations[self.language]['added_path'].format(path=os.path.basename(path)))
            logging.info(f"Added path: {path}")

    def remove_path(self):
        try:
            index = self.paths_listbox.curselection()[0]
            path_entry = self.paths_listbox.get(index)
            if path_entry.startswith("[Scheduled] "):
                path = path_entry[11:]
                self.backup_manager.config['scheduled_paths'].remove(path)
            else:
                path = path_entry
                self.backup_manager.config['paths'].remove(path)
            self.paths_listbox.delete(index)
            self.backup_manager.save_config()
            self.status_var.set(self.translations[self.language]['removed_path'].format(path=os.path.basename(path)))
            logging.info(f"Removed path: {path}")
        except IndexError:
            messagebox.showerror("Error", self.translations[self.language]['no_path_selected'])
            self.status_var.set(self.translations[self.language]['no_path_selected'])

    def create_backup(self):
        self.status_var.set(self.translations[self.language]['ready'])
        self.root.update()
        password = self.password_entry.get() or None
        if password and len(password) < 8:
            messagebox.showerror("Error", self.translations[self.language]['weak_password'])
            self.status_var.set(self.translations[self.language]['weak_password'])
            return
        if self.backup_manager.create_backup(password=password):
            messagebox.showinfo("Success", self.translations[self.language]['backup_success'], icon="info")
            self.status_var.set(self.translations[self.language]['backup_success'])
            self.backup_combobox.configure(values=self.get_backups())
        else:
            messagebox.showerror("Error", self.translations[self.language]['backup_failed'])
            self.status_var.set(self.translations[self.language]['backup_failed'])

    def get_backups(self):
        return [f for f in os.listdir(self.backup_manager.backup_dir) if f.endswith('.zip')]

    def restore_backup(self):
        backup_name = self.backup_combobox.get()
        if not backup_name:
            messagebox.showerror("Error", self.translations[self.language]['no_backup_selected'])
            self.status_var.set(self.translations[self.language]['no_backup_selected'])
            return
        restore_dir = filedialog.askdirectory()
        if not restore_dir:
            self.status_var.set(self.translations[self.language]['restore_cancelled'])
            return
        
        self.status_var.set(self.translations[self.language]['ready'])
        self.root.update()

        password = None
        if self.backup_manager.is_backup_encrypted(backup_name):
            dialog = ctk.CTkToplevel(self.root)
            dialog.title(self.translations[self.language]['restore_backup'])
            dialog.geometry("400x200")
            dialog.transient(self.root)
            dialog.grab_set()

            label = ctk.CTkLabel(dialog, text=self.translations[self.language]['enter_restore_password'], font=("Arial", 14))
            label.pack(pady=10)

            entry = ctk.CTkEntry(dialog, show="*", width=300, font=("Arial", 12))
            entry.pack(pady=10)

            def confirm():
                nonlocal password
                password = entry.get()
                dialog.destroy()

            confirm_button = ctk.CTkButton(dialog, text=self.translations[self.language]['confirm'], command=confirm, font=("Arial", 14))
            confirm_button.pack(pady=10)

            dialog.wait_window()
            if password is None:
                self.status_var.set(self.translations[self.language]['restore_cancelled'])
                return
            if len(password) < 8:
                messagebox.showerror("Error", self.translations[self.language]['weak_password'])
                self.status_var.set(self.translations[self.language]['weak_password'])
                return
        
        result = self.backup_manager.restore_backup(backup_name, restore_dir, password)
        if result:
            messagebox.showinfo("Success", self.translations[self.language]['restore_success'], icon="info")
            self.status_var.set(self.translations[self.language]['restore_success'])
        else:
            if password and self.backup_manager.is_backup_encrypted(backup_name):
                messagebox.showerror("Error", self.translations[self.language]['invalid_password'])
                self.status_var.set(self.translations[self.language]['invalid_password'])
            else:
                messagebox.showerror("Error", self.translations[self.language]['restore_failed'])
                self.status_var.set(self.translations[self.language]['restore_failed'])

    def check_integrity(self):
        backup_name = self.backup_combobox.get()
        if not backup_name:
            messagebox.showerror("Error", self.translations[self.language]['no_backup_selected'])
            self.status_var.set(self.translations[self.language]['no_backup_selected'])
            return
        
        backup_path = os.path.join(self.backup_manager.backup_dir, backup_name)
        try:
            if self.backup_manager.verify_checksum(backup_path):
                messagebox.showinfo("Success", self.translations[self.language]['backup_valid'].format(name=backup_name), icon="info")
                self.status_var.set(self.translations[self.language]['backup_valid'].format(name=backup_name))
                logging.info(f"Integrity check passed for {backup_name}")
            else:
                messagebox.showerror("Error", self.translations[self.language]['backup_corrupted'].format(name=backup_name))
                self.status_var.set(self.translations[self.language]['backup_corrupted'].format(name=backup_name))
                logging.error(f"Integrity check failed for {backup_name}")
        except Exception as e:
            messagebox.showerror("Error", self.translations[self.language]['integrity_check_failed'].format(name=backup_name))
            self.status_var.set(self.translations[self.language]['integrity_check_failed'].format(name=backup_name))
            logging.error(f"Integrity check error for {backup_name}: {str(e)}")

    def start_schedule(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(self.translations[self.language]['schedule_dialog_title'])
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()

        paths_label = ctk.CTkLabel(dialog, text=self.translations[self.language]['schedule_paths'], font=("Arial", 14))
        paths_label.pack(anchor="w", padx=15, pady=5)

        paths_listbox = tk.Listbox(dialog, width=60, height=8, font=("Arial", 12), bg="#333333", fg="#E0E0E0", selectbackground="#007ACC", selectforeground="#E0E0E0", relief="flat", borderwidth=1)
        paths_listbox.pack(fill="x", padx=15, pady=5)
        for path in self.backup_manager.config['scheduled_paths']:
            paths_listbox.insert(tk.END, path)

        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(fill="x", padx=15, pady=5)

        add_path_button = ctk.CTkButton(button_frame, text=self.translations[self.language]['add_path'], command=lambda: self.add_path_to_dialog(paths_listbox), font=("Arial", 14))
        add_path_button.pack(side="left", padx=5)

        remove_path_button = ctk.CTkButton(button_frame, text=self.translations[self.language]['remove_path'], command=lambda: self.remove_path_from_dialog(paths_listbox), font=("Arial", 14))
        remove_path_button.pack(side="left", padx=5)

        password_label = ctk.CTkLabel(dialog, text=self.translations[self.language]['schedule_password'], font=("Arial", 14))
        password_label.pack(anchor="w", padx=15, pady=5)

        password_entry = ctk.CTkEntry(dialog, show="*", width=300, font=("Arial", 12))
        password_entry.pack(anchor="w", padx=15)
        if self.backup_manager.config.get('scheduled_password'):
            password_entry.insert(0, self.backup_manager.config['scheduled_password'])

        action_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        action_frame.pack(fill="x", padx=15, pady=15)

        confirm_button = ctk.CTkButton(action_frame, text=self.translations[self.language]['confirm'], command=lambda: self.confirm_schedule(dialog, paths_listbox, password_entry, self.schedule_var.get()), font=("Arial", 14))
        confirm_button.pack(side="left", padx=5)

        cancel_button = ctk.CTkButton(action_frame, text=self.translations[self.language]['cancel'], command=dialog.destroy, font=("Arial", 14))
        cancel_button.pack(side="left", padx=5)

    def add_path_to_dialog(self, listbox):
        path = filedialog.askopenfilename() or filedialog.askdirectory()
        if path and path not in listbox.get(0, tk.END):
            path = os.path.normpath(path)
            if not os.path.exists(path):
                messagebox.showerror("Error", f"Path does not exist: {path}")
                return
            listbox.insert(tk.END, path)
            logging.info(f"Added scheduled path: {path}")

    def remove_path_from_dialog(self, listbox):
        try:
            index = listbox.curselection()[0]
            path = listbox.get(index)
            listbox.delete(index)
            logging.info(f"Removed scheduled path: {path}")
        except IndexError:
            messagebox.showerror("Error", self.translations[self.language]['no_path_selected'])

    def confirm_schedule(self, dialog, paths_listbox, password_entry, frequency):
        paths = list(paths_listbox.get(0, tk.END))
        password = password_entry.get() or None
        if not paths:
            messagebox.showerror("Error", self.translations[self.language]['no_paths_for_schedule'])
            return
        if password and len(password) < 8:
            messagebox.showerror("Error", self.translations[self.language]['weak_password'])
            return
        
        self.backup_manager.config['scheduled_paths'] = [os.path.normpath(p) for p in paths]
        self.backup_manager.config['scheduled_password'] = password
        self.backup_manager.save_config()

        self.paths_listbox.delete(0, tk.END)
        for path in self.backup_manager.config['paths']:
            self.paths_listbox.insert(tk.END, path)
        for path in self.backup_manager.config['scheduled_paths']:
            self.paths_listbox.insert(tk.END, f"[Scheduled] {path}")

        if self.scheduler.schedule_backup(frequency):
            freq = self.translations[self.language][frequency]
            messagebox.showinfo("Success", self.translations[self.language]['schedule_started'].format(freq=freq), icon="info")
            self.status_var.set(self.translations[self.language]['schedule_started'].format(freq=freq))
            self.schedule_status_var.set(self.translations[self.language]['schedule_status'].format(status=self.translations[self.language]['enabled']))
        else:
            messagebox.showerror("Error", self.translations[self.language]['schedule_failed'])
            self.status_var.set(self.translations[self.language]['schedule_failed'])
        dialog.destroy()

    def stop_schedule(self):
        self.scheduler.stop()
        self.schedule_status_var.set(self.translations[self.language]['schedule_status'].format(status=self.translations[self.language]['disabled']))
        messagebox.showinfo("Success", self.translations[self.language]['schedule_stopped'], icon="info")
        self.status_var.set(self.translations[self.language]['schedule_stopped'])

    def view_logs(self):
        logs = self.log_manager.get_logs()
        log_window = ctk.CTkToplevel(self.root)
        log_window.title(self.translations[self.language]['logs_reports'])
        log_window.geometry("800x600")

        text_area = ctk.CTkTextbox(log_window, height=20, width=80, font=("Arial", 12))
        text_area.insert("0.0", logs)
        text_area.pack(padx=15, pady=15, fill="both", expand=True)
        text_area.configure(state="disabled")
        
        self.status_var.set(self.translations[self.language]['viewing_logs'])

    def export_report(self):
        output_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if output_path:
            self.log_manager.export_report(output_path)
            messagebox.showinfo("Success", self.translations[self.language]['report_exported'].format(path=os.path.basename(output_path)), icon="info")
            self.status_var.set(self.translations[self.language]['report_exported'].format(path=os.path.basename(output_path)))
        else:
            self.status_var.set(self.translations[self.language]['report_cancelled'])

    def run(self):
        self.root.mainloop()
