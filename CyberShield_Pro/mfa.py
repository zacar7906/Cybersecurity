import pyotp
import qrcode
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLineEdit, QLabel, QMessageBox, QHBoxLayout
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import QTimer
from io import BytesIO

class MFATab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        # Clave secreta para generar OTPs
        self.secret = pyotp.random_base32()

        # Mostrar la clave secreta al usuario
        self.secret_label = QLabel(f"Clave secreta: {self.secret}")
        layout.addWidget(self.secret_label)

        # Campo de entrada para el código OTP
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText('Introduce el código OTP')
        layout.addWidget(self.otp_input)

        # Botón para verificar OTP
        self.verify_button = QPushButton('Verificar OTP')
        self.verify_button.clicked.connect(self.verify_otp)
        layout.addWidget(self.verify_button)

        # Mostrar el tiempo restante para el código OTP actual
        self.timer_label = QLabel()
        layout.addWidget(self.timer_label)

        # Botón para regenerar la clave secreta
        self.regen_secret_button = QPushButton('Regenerar Clave Secreta')
        self.regen_secret_button.clicked.connect(self.regenerate_secret)
        layout.addWidget(self.regen_secret_button)

        # Botón para mostrar el código QR de la clave secreta
        self.qr_button = QPushButton('Mostrar Código QR')
        self.qr_button.clicked.connect(self.show_qr_code)
        layout.addWidget(self.qr_button)

        # Espacio para mostrar el código QR
        self.qr_label = QLabel()
        layout.addWidget(self.qr_label)

        # Iniciar el temporizador para actualizar el tiempo restante del OTP
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time_remaining)
        self.timer.start(1000)  # Actualizar cada segundo

        self.setLayout(layout)

    def update_time_remaining(self):
        """Actualiza el tiempo restante antes de que el código OTP caduque."""
        totp = pyotp.TOTP(self.secret)
        time_remaining = totp.interval - (totp.timecode(pyotp.time.time()) % totp.interval)
        self.timer_label.setText(f"Tiempo restante para el siguiente OTP: {time_remaining}s")

    def verify_otp(self):
        """Verifica el código OTP ingresado por el usuario."""
        otp = self.otp_input.text()

        # Validar que el OTP sea numérico
        if not otp.isdigit():
            QMessageBox.warning(self, "Error", "El código OTP debe ser numérico")
            return

        totp = pyotp.TOTP(self.secret)

        if totp.verify(otp):
            QMessageBox.information(self, "Éxito", "Código OTP verificado correctamente")
        else:
            QMessageBox.warning(self, "Error", "Código OTP incorrecto")

    def regenerate_secret(self):
        """Genera una nueva clave secreta y la muestra al usuario."""
        self.secret = pyotp.random_base32()
        self.secret_label.setText(f"Clave secreta: {self.secret}")
        QMessageBox.information(self, "Clave regenerada", "Se ha generado una nueva clave secreta")

    def show_qr_code(self):
        """Genera y muestra un código QR con la clave secreta para escanearla en una app de autenticación."""
        totp = pyotp.TOTP(self.secret)
        otp_uri = totp.provisioning_uri(name="usuario@ejemplo.com", issuer_name="CyberSecurityApp")
        
        # Generar el código QR a partir del URI
        qr = qrcode.QRCode()
        qr.add_data(otp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        pixmap = QPixmap()
        pixmap.loadFromData(buffer.getvalue())

        # Mostrar el código QR en la interfaz
        self.qr_label.setPixmap(pixmap)
        self.qr_label.setScaledContents(True)
        self.qr_label.setFixedSize(200, 200)
