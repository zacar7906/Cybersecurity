import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel
from modules.vulnerability_scan import VulnerabilityScanTab
from modules.penetration_testing import PenetrationTestingTab
from modules.network_monitoring import NetworkMonitoringTab
from modules.encryption_decryption import EncryptionDecryptionTab
from modules.forensic_analysis import ForensicAnalysisTab
from modules.password_manager import PasswordManagerTab
from modules.firewall_management import FirewallManagementTab

class CyberSecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('CyberSecurity Suite - Grado Militar')
        self.setGeometry(100, 100, 1200, 800)
        
        # Crear el TabWidget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Añadir pestañas
        self.tabs.addTab(VulnerabilityScanTab(), "Escaneo de Vulnerabilidades")
        self.tabs.addTab(PenetrationTestingTab(), "Pruebas de Penetración")
        self.tabs.addTab(NetworkMonitoringTab(), "Monitoreo de Red")
        self.tabs.addTab(EncryptionDecryptionTab(), "Cifrado y Descifrado")
        self.tabs.addTab(ForensicAnalysisTab(), "Análisis Forense")
        self.tabs.addTab(PasswordManagerTab(), "Gestión de Contraseñas")
        self.tabs.addTab(FirewallManagementTab(), "Firewall Avanzado")
        
        self.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CyberSecurityApp()
    sys.exit(app.exec_())
