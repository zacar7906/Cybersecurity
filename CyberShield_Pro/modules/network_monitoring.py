# modules/network_monitoring.py

import pyqtgraph as pg
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import pyshark
import time

class PacketSnifferThread(QThread):
    # Señal para enviar el número de bytes capturados
    data_signal = pyqtSignal(int)
    error_signal = pyqtSignal(str)

    def __init__(self, interface, bpf_filter):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = True

    def run(self):
        try:
            # Crear el capturador de paquetes
            self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter)
            self.capture.sniff_continuously(packet_count=None)

            for packet in self.capture:
                if not self.running:
                    break
                try:
                    packet_length = int(packet.length)
                    self.data_signal.emit(packet_length)
                except AttributeError:
                    continue  # Si el paquete no tiene longitud, lo ignoramos
        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        self.running = False
        self.capture.close()

class NetworkMonitoringTab(QWidget):
    def __init__(self):
        super().__init__()

        # Inicializar variables para el gráfico
        self.data = []
        self.times = []
        self.start_time = time.time()

        # Crear el diseño de la interfaz
        main_layout = QVBoxLayout()

        # Controles de inicio y detención
        controls_layout = QHBoxLayout()

        self.interface_input = QLineEdit()
        self.interface_input.setPlaceholderText("Interface (e.g., eth0)")

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filtro BPF (opcional)")

        self.start_button = QPushButton('Iniciar Monitorización')
        self.start_button.clicked.connect(self.start_network_capture)

        self.stop_button = QPushButton('Detener Monitorización')
        self.stop_button.clicked.connect(self.stop_network_capture)
        self.stop_button.setEnabled(False)

        controls_layout.addWidget(QLabel("Interfaz:"))
        controls_layout.addWidget(self.interface_input)
        controls_layout.addWidget(QLabel("Filtro:"))
        controls_layout.addWidget(self.filter_input)
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)

        # Configurar el gráfico en tiempo real
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setTitle('Monitoreo de Tráfico en Tiempo Real')
        self.plot_widget.setLabel('left', 'Bytes por segundo')
        self.plot_widget.setLabel('bottom', 'Tiempo (s)')

        self.plot_curve = self.plot_widget.plot(self.times, self.data, pen='y')

        # Añadir widgets al layout principal
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.plot_widget)

        self.setLayout(main_layout)

        # Timer para actualizar el gráfico
        self.timer = QTimer()
        self.timer.setInterval(1000)  # Actualizar cada segundo
        self.timer.timeout.connect(self.update_plot)

        # Variable para almacenar los bytes por segundo
        self.bytes_per_second = 0

    def start_network_capture(self):
        interface = self.interface_input.text()
        bpf_filter = self.filter_input.text()

        if not interface:
            self.show_error("Por favor, ingrese una interfaz de red válida.")
            return

        # Deshabilitar el botón de inicio y habilitar el de detención
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        # Reiniciar los datos
        self.data = []
        self.times = []
        self.start_time = time.time()

        # Iniciar el hilo de captura
        self.sniffer_thread = PacketSnifferThread(interface, bpf_filter)
        self.sniffer_thread.data_signal.connect(self.process_packet)
        self.sniffer_thread.error_signal.connect(self.show_error)
        self.sniffer_thread.start()

        # Iniciar el timer para actualizar el gráfico
        self.timer.start()

    def stop_network_capture(self):
        # Detener el hilo de captura
        if hasattr(self, 'sniffer_thread'):
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        # Detener el timer
        self.timer.stop()

        # Habilitar el botón de inicio y deshabilitar el de detención
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def process_packet(self, packet_length):
        # Acumular los bytes capturados
        self.bytes_per_second += packet_length

    def update_plot(self):
        # Calcular el tiempo transcurrido
        current_time = time.time() - self.start_time

        # Añadir los datos actuales al historial
        self.times.append(current_time)
        self.data.append(self.bytes_per_second)

        # Actualizar el gráfico
        self.plot_curve.setData(self.times, self.data)

        # Resetear el contador de bytes para el próximo intervalo
        self.bytes_per_second = 0

    def show_error(self, error_message):
        # Mostrar el mensaje de error en algún lugar de la interfaz o mediante un QMessageBox
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.critical(self, "Error", error_message)

        # Detener la captura si hay un error
        self.stop_network_capture()
