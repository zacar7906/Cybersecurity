from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QMessageBox
import base64
import os

class EncryptionDecryptionTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        # Inputs y botones
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText('Introduce la clave de cifrado AES-256 o Fernet (32 bytes)')
        
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText('Introduce el texto a cifrar o descifrar')

        self.result_area = QTextEdit()
        self.result_area.setPlaceholderText('Resultado (texto cifrado o descifrado)')
        self.result_area.setReadOnly(True)

        self.encrypt_button = QPushButton('Cifrar')
        self.encrypt_button.clicked.connect(self.encrypt_text)

        self.decrypt_button = QPushButton('Descifrar')
        self.decrypt_button.clicked.connect(self.decrypt_text)

        self.generate_key_button = QPushButton('Generar clave Fernet')
        self.generate_key_button.clicked.connect(self.generate_fernet_key)

        layout.addWidget(QLabel("Clave de cifrado:"))
        layout.addWidget(self.key_input)
        layout.addWidget(QLabel("Texto a cifrar/descifrar:"))
        layout.addWidget(self.text_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.generate_key_button)
        layout.addWidget(QLabel("Resultado:"))
        layout.addWidget(self.result_area)

        self.setLayout(layout)

    def generate_fernet_key(self):
        """Generar una clave Fernet y colocarla en el input de clave"""
        key = Fernet.generate_key()
        self.key_input.setText(key.decode())
        self.show_message("Clave Fernet generada exitosamente", "Clave generada", key.decode())

    def show_message(self, message, title="Info", detailed_text=None):
        """Mostrar un cuadro de mensaje con información"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        if detailed_text:
            msg.setDetailedText(detailed_text)
        msg.exec_()

    def encrypt_text(self):
        """Cifrar el texto con la clave introducida usando Fernet o AES-256"""
        key = self.key_input.text().encode()
        text = self.text_input.toPlainText().encode()

        # Verificar longitud de clave
        if len(key) == 44:  # Longitud de una clave base64 de 32 bytes para Fernet
            try:
                f = Fernet(key)
                encrypted_text = f.encrypt(text)
                self.result_area.setText(encrypted_text.decode())
            except Exception as e:
                self.show_message(f"Error al cifrar con Fernet: {e}", "Error")
        elif len(key) == 32:  # Longitud para AES-256
            try:
                encrypted_text = self.encrypt_aes256(text, key)
                self.result_area.setText(base64.b64encode(encrypted_text).decode())  # Mostrar en base64
            except Exception as e:
                self.show_message(f"Error al cifrar con AES-256: {e}", "Error")
        else:
            self.show_message("Clave no válida. Debe ser una clave Fernet de 32 bytes en base64 o una clave AES-256 de 32 bytes.")

    def decrypt_text(self):
        """Descifrar el texto con la clave introducida usando Fernet o AES-256"""
        key = self.key_input.text().encode()
        encrypted_text = self.text_input.toPlainText().encode()

        # Verificar longitud de clave
        if len(key) == 44:  # Fernet key (32 bytes en base64)
            try:
                f = Fernet(key)
                decrypted_text = f.decrypt(encrypted_text)
                self.result_area.setText(decrypted_text.decode())
            except Exception as e:
                self.show_message(f"Error al descifrar con Fernet: {e}", "Error")
        elif len(key) == 32:  # AES-256 key
            try:
                decrypted_text = self.decrypt_aes256(base64.b64decode(encrypted_text), key)
                self.result_area.setText(decrypted_text.decode())
            except Exception as e:
                self.show_message(f"Error al descifrar con AES-256: {e}", "Error")
        else:
            self.show_message("Clave no válida. Debe ser una clave Fernet de 32 bytes en base64 o una clave AES-256 de 32 bytes.")

    def encrypt_aes256(self, plaintext, key):
        """Cifrado AES-256 con modo CBC"""
        # Generar un IV (vector de inicialización) aleatorio
        iv = os.urandom(16)

        # Crear un padding de 128 bits (16 bytes) para hacer que el texto tenga longitud múltiplo de bloque
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Configurar el cifrador AES-256
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Cifrar el texto plano
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Devolver el IV concatenado con el texto cifrado (el IV debe transmitirse junto con los datos cifrados)
        return iv + encrypted

    def decrypt_aes256(self, ciphertext, key):
        """Descifrado AES-256 con modo CBC"""
        # El IV es la primera parte del ciphertext (los primeros 16 bytes)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]

        # Configurar el descifrador AES-256
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Descifrar el texto
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        # Eliminar el padding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted) + unpadder.finalize()

        return unpadded_data
