import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QMessageBox

class FirewallManagementTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)

        # Botones y campos para reglas de firewall
        self.iptables_button = QPushButton('Mostrar Reglas IPTables')
        self.iptables_button.clicked.connect(self.show_iptables_rules)

        self.ufw_button = QPushButton('Mostrar Reglas UFW')
        self.ufw_button.clicked.connect(self.show_ufw_rules)

        self.add_iptables_rule_button = QPushButton('Añadir Regla a IPTables')
        self.add_iptables_rule_button.clicked.connect(self.add_iptables_rule)

        self.delete_iptables_rule_button = QPushButton('Eliminar Regla de IPTables')
        self.delete_iptables_rule_button.clicked.connect(self.delete_iptables_rule)

        # Inputs para reglas personalizadas de IPTables
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Introduce el puerto para permitir")

        self.protocol_input = QLineEdit()
        self.protocol_input.setPlaceholderText("Introduce el protocolo (tcp/udp)")

        layout.addWidget(self.iptables_button)
        layout.addWidget(self.ufw_button)
        layout.addWidget(self.port_input)
        layout.addWidget(self.protocol_input)
        layout.addWidget(self.add_iptables_rule_button)
        layout.addWidget(self.delete_iptables_rule_button)
        layout.addWidget(self.result_area)
        self.setLayout(layout)

    def show_iptables_rules(self):
        """Muestra las reglas actuales de IPTables"""
        process = subprocess.Popen(['sudo', 'iptables', '-L'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if err:
            self.result_area.setText(f"Error al mostrar las reglas IPTables: {err.decode()}")
        else:
            self.result_area.setText(out.decode())

    def show_ufw_rules(self):
        """Muestra el estado y las reglas actuales de UFW"""
        process = subprocess.Popen(['sudo', 'ufw', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if err:
            self.result_area.setText(f"Error al mostrar las reglas UFW: {err.decode()}")
        else:
            self.result_area.setText(out.decode())

    def add_iptables_rule(self):
        """Añade una regla personalizada de IPTables basada en el puerto y protocolo ingresados"""
        port = self.port_input.text()
        protocol = self.protocol_input.text()

        if not port or not protocol:
            QMessageBox.warning(self, "Error", "Por favor, introduce un puerto y un protocolo.")
            return

        # Añadir regla IPTables para el puerto y protocolo especificado
        process = subprocess.Popen(['sudo', 'iptables', '-A', 'INPUT', '-p', protocol, '--dport', port, '-j', 'ACCEPT'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()

        if err:
            self.result_area.setText(f"Error al añadir la regla de IPTables: {err.decode()}")
        else:
            self.result_area.setText(f"Regla añadida correctamente para permitir {protocol.upper()} en el puerto {port}.")

    def delete_iptables_rule(self):
        """Elimina una regla personalizada de IPTables basada en el puerto y protocolo ingresados"""
        port = self.port_input.text()
        protocol = self.protocol_input.text()

        if not port or not protocol:
            QMessageBox.warning(self, "Error", "Por favor, introduce un puerto y un protocolo para eliminar la regla.")
            return

        # Eliminar regla IPTables para el puerto y protocolo especificado
        process = subprocess.Popen(['sudo', 'iptables', '-D', 'INPUT', '-p', protocol, '--dport', port, '-j', 'ACCEPT'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()

        if err:
            self.result_area.setText(f"Error al eliminar la regla de IPTables: {err.decode()}")
        else:
            self.result_area.setText(f"Regla eliminada correctamente para {protocol.upper()} en el puerto {port}.")
