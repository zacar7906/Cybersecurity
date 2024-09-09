import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QComboBox
from PyQt5.QtCore import QThread, pyqtSignal

class PenetrationTestingThread(QThread):
    # Señales para comunicar resultados y errores
    result_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, url, attack_type):
        super().__init__()
        self.url = url
        self.attack_type = attack_type

    def run(self):
        try:
            # Selección del tipo de ataque basado en el ataque seleccionado
            if self.attack_type == "Ataque Básico":
                command = ['sqlmap', '-u', self.url, '--batch']
            elif self.attack_type == "Dumping de Base de Datos":
                command = ['sqlmap', '-u', self.url, '--batch', '--dump']
            elif self.attack_type == "Prueba de Vulnerabilidad":
                command = ['sqlmap', '-u', self.url, '--batch', '--level=5', '--risk=3']
            else:
                raise ValueError("Tipo de ataque desconocido")

            # Ejecutar el comando de sqlmap
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = process.communicate()

            # Si hay errores, emitir señal de error
            if process.returncode != 0:
                self.error_signal.emit(err.decode())
            else:
                self.result_signal.emit(out.decode())

        except Exception as e:
            self.error_signal.emit(str(e))


class PenetrationTestingTab(QWidget):
    def __init__(self):
        super().__init__()

        # Crear el diseño de la interfaz
        layout = QVBoxLayout()

        # Campo para ingresar la URL
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Ingrese la URL objetivo para SQLMap")

        # Selector de tipo de ataque
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(["Ataque Básico", "Dumping de Base de Datos", "Prueba de Vulnerabilidad"])

        # Botón para iniciar el ataque
        self.attack_button = QPushButton('Iniciar Ataque SQLMap')
        self.attack_button.clicked.connect(self.start_attack)

        # Área de texto para mostrar los resultados
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)

        # Mensaje de estado
        self.status_label = QLabel("Estado: Esperando ataque...")

        # Añadir widgets al layout
        layout.addWidget(QLabel("URL objetivo:"))
        layout.addWidget(self.url_input)
        layout.addWidget(QLabel("Seleccione el tipo de ataque:"))
        layout.addWidget(self.attack_type_combo)
        layout.addWidget(self.attack_button)
        layout.addWidget(self.status_label)
        layout.addWidget(self.result_area)
        self.setLayout(layout)

    def start_attack(self):
        url = self.url_input.text()

        # Validación básica de la URL
        if not url:
            self.status_label.setText("Error: Ingrese una URL válida.")
            return

        attack_type = self.attack_type_combo.currentText()

        # Actualizar el estado a "En progreso"
        self.status_label.setText("Estado: Ataque en progreso...")

        # Iniciar el ataque en un hilo separado
        self.attack_thread = PenetrationTestingThread(url, attack_type)
        self.attack_thread.result_signal.connect(self.display_results)
        self.attack_thread.error_signal.connect(self.display_error)
        self.attack_thread.start()

    def display_results(self, results):
        self.status_label.setText("Estado: Ataque completado.")
        self.result_area.setText(results)

    def display_error(self, error_message):
        self.status_label.setText("Estado: Error durante el ataque.")
        self.result_area.setText(f"Error: {error_message}")
