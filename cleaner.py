import shutil

class Cleaner:
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager

    def check_disk_space(self, required_space):
        total, used, free = shutil.disk_usage(self.backup_manager.backup_dir)
        return free > required_space
