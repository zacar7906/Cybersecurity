from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QMessageBox, QFileDialog
import os
import hashlib

class PasswordManagerTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText('Introduce la clave de cifrado o genera una nueva')

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Introduce la contraseña a guardar')

        self.generate_key_button = QPushButton('Generar Clave')
        self.generate_key_button.clicked.connect(self.generate_key)

        self.encrypt_button = QPushButton('Guardar Contraseña')
        self.encrypt_button.clicked.connect(self.encrypt_password)

        self.decrypt_button = QPushButton('Ver Contraseñas Guardadas')
        self.decrypt_button.clicked.connect(self.decrypt_password)

        self.search_password_button = QPushButton('Buscar Contraseña')
        self.search_password_button.clicked.connect(self.search_password)

        self.delete_password_button = QPushButton('Eliminar Contraseña')
        self.delete_password_button.clicked.connect(self.delete_password)

        self.password_output = QTextEdit()
        self.password_output.setReadOnly(True)

        layout.addWidget(self.key_input)
        layout.addWidget(self.generate_key_button)
        layout.addWidget(self.password_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.search_password_button)
        layout.addWidget(self.delete_password_button)
        layout.addWidget(self.password_output)
        self.setLayout(layout)

        self.password_file = "passwords.txt"

    def generate_key(self):
        """Genera una nueva clave de cifrado y la muestra al usuario"""
        key = Fernet.generate_key()
        self.key_input.setText(key.decode())
        QMessageBox.information(self, "Clave Generada", "Se ha generado una nueva clave de cifrado.\nAsegúrate de guardarla de manera segura.")

    def encrypt_password(self):
        key = self.key_input.text().encode()
        password = self.password_input.text().encode()

        if not key or not password:
            QMessageBox.warning(self, "Error", "Por favor introduce una clave y una contraseña")
            return

        # Validar longitud de la clave (debe ser 32 bytes)
        try:
            f = Fernet(key)
        except ValueError:
            QMessageBox.warning(self, "Error", "La clave proporcionada no es válida. Debe ser de 32 bytes en formato base64.")
            return

        encrypted_password = f.encrypt(password)

        # Aplicar hashing al nombre de la contraseña para mayor seguridad
        hashed_password = hashlib.sha256(password).hexdigest()

        # Guardar contraseña cifrada en el archivo
        with open(self.password_file, "a") as file:
            file.write(f"{hashed_password}:{encrypted_password.decode()}\n")

        QMessageBox.information(self, "Éxito", "Contraseña guardada correctamente")
        self.password_input.clear()

    def decrypt_password(self):
        key = self.key_input.text().encode()

        if not key:
            QMessageBox.warning(self, "Error", "Por favor introduce una clave válida")
            return

        # Validar longitud de la clave
        try:
            f = Fernet(key)
        except ValueError:
            QMessageBox.warning(self, "Error", "La clave proporcionada no es válida.")
            return

        # Leer y descifrar contraseñas
        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as file:
                lines = file.readlines()

            decrypted_passwords = []
            for line in lines:
                hashed_password, enc_pass = line.strip().split(':')
                try:
                    decrypted_password = f.decrypt(enc_pass.encode()).decode()
                    decrypted_passwords.append(f"{hashed_password}: {decrypted_password}")
                except InvalidToken:
                    decrypted_passwords.append(f"{hashed_password}: Error al descifrar con la clave proporcionada")

            self.password_output.setText("\n".join(decrypted_passwords))
        else:
            self.password_output.setText("No hay contraseñas guardadas.")

    def search_password(self):
        """Busca una contraseña en el archivo según la contraseña en texto plano"""
        key = self.key_input.text().encode()
        search_password = self.password_input.text().encode()

        if not key or not search_password:
            QMessageBox.warning(self, "Error", "Por favor introduce una clave y la contraseña a buscar")
            return

        # Validar longitud de la clave
        try:
            f = Fernet(key)
        except ValueError:
            QMessageBox.warning(self, "Error", "La clave proporcionada no es válida.")
            return

        hashed_password = hashlib.sha256(search_password).hexdigest()

        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as file:
                lines = file.readlines()

            for line in lines:
                stored_hash, enc_pass = line.strip().split(':')
                if stored_hash == hashed_password:
                    try:
                        decrypted_password = f.decrypt(enc_pass.encode()).decode()
                        QMessageBox.information(self, "Contraseña Encontrada", f"La contraseña es: {decrypted_password}")
                        return
                    except InvalidToken:
                        QMessageBox.warning(self, "Error", "No se puede descifrar con la clave proporcionada.")
                        return

            QMessageBox.warning(self, "Error", "Contraseña no encontrada.")
        else:
            QMessageBox.warning(self, "Error", "No hay contraseñas guardadas.")

    def delete_password(self):
        """Elimina una contraseña guardada"""
        search_password = self.password_input.text().encode()

        if not search_password:
            QMessageBox.warning(self, "Error", "Por favor introduce la contraseña a eliminar")
            return

        hashed_password = hashlib.sha256(search_password).hexdigest()

        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as file:
                lines = file.readlines()

            with open(self.password_file, "w") as file:
                for line in lines:
                    stored_hash, enc_pass = line.strip().split(':')
                    if stored_hash != hashed_password:
                        file.write(line)

            QMessageBox.information(self, "Éxito", "Contraseña eliminada correctamente")
        else:
            QMessageBox.warning(self, "Error", "No hay contraseñas guardadas.")
