import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Encryptor:
    # Ініціалізація об'єкта шифрування з паролем 
    def __init__(self, password=None, salt=None):
        self.key = None
        self.salt = salt
        if password and salt:
            self.derive_key(password, salt)

    # Генерація ключа шифрування на основі пароля 
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.key = key

    # Шифрування файлу за вказаним шляхом
    def encrypt_file(self, input_path, output_path):
        if not self.key:
            shutil.copy(input_path, output_path)  # Якщо ключа немає, просто копіюємо файл
            return
        fernet = Fernet(self.key)
        with open(input_path, 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(encrypted)

    # Розшифрування файлу за вказаним шляхом
    def decrypt_file(self, input_path, output_path):
        if not self.key:
            shutil.copy(input_path, output_path)  # Якщо ключа немає, просто копіюємо файл
            return
        fernet = Fernet(self.key)
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        with open(output_path, 'wb') as f:
            f.write(decrypted)
