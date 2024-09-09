import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QMessageBox

class ForensicAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)

        self.select_disk_button = QPushButton('Seleccionar disco o imagen')
        self.select_disk_button.clicked.connect(self.select_disk)

        self.analyze_fls_button = QPushButton('Analizar con fls (Listado de Archivos)')
        self.analyze_fls_button.clicked.connect(self.run_fls_analysis)

        self.analyze_mmls_button = QPushButton('Mostrar tabla de particiones (mmls)')
        self.analyze_mmls_button.clicked.connect(self.run_mmls_analysis)

        self.extract_file_button = QPushButton('Extraer archivo con icat')
        self.extract_file_button.clicked.connect(self.extract_file_with_icat)

        layout.addWidget(self.select_disk_button)
        layout.addWidget(self.analyze_fls_button)
        layout.addWidget(self.analyze_mmls_button)
        layout.addWidget(self.extract_file_button)
        layout.addWidget(self.result_area)
        self.setLayout(layout)

        self.selected_disk = None

    def select_disk(self):
        file_dialog = QFileDialog()
        self.selected_disk, _ = file_dialog.getOpenFileName(self, "Seleccionar disco o imagen", "", "Imágenes de disco (*.img *.dd *.raw *.e01)")
        if self.selected_disk:
            self.result_area.setText(f"Disco seleccionado: {self.selected_disk}")
        else:
            self.result_area.setText("No se seleccionó ningún disco o imagen.")

    def run_fls_analysis(self):
        """Realiza un listado de archivos del disco o imagen seleccionada utilizando SleuthKit (fls)"""
        if self.selected_disk:
            try:
                process = subprocess.Popen(['fls', '-r', self.selected_disk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = process.communicate()
                if err:
                    self.result_area.setText(f"Error: {err.decode()}")
                else:
                    self.result_area.setText(out.decode())
            except Exception as e:
                self.show_error_message(f"Error ejecutando fls: {e}")
        else:
            self.result_area.setText("Por favor selecciona un disco o imagen primero.")

    def run_mmls_analysis(self):
        """Realiza el análisis de la tabla de particiones con mmls"""
        if self.selected_disk:
            try:
                process = subprocess.Popen(['mmls', self.selected_disk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = process.communicate()
                if err:
                    self.result_area.setText(f"Error: {err.decode()}")
                else:
                    self.result_area.setText(out.decode())
            except Exception as e:
                self.show_error_message(f"Error ejecutando mmls: {e}")
        else:
            self.result_area.setText("Por favor selecciona un disco o imagen primero.")

    def extract_file_with_icat(self):
        """Extrae un archivo específico utilizando icat"""
        if self.selected_disk:
            inode, ok = self.get_user_input("Introduce el número de inode del archivo a extraer:")
            if ok and inode:
                output_path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo extraído", "", "Todos los archivos (*)")
                if output_path:
                    try:
                        process = subprocess.Popen(['icat', self.selected_disk, inode], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        out, err = process.communicate()
                        if err:
                            self.result_area.setText(f"Error: {err.decode()}")
                        else:
                            with open(output_path, 'wb') as f:
                                f.write(out)
                            self.result_area.setText(f"Archivo extraído y guardado en: {output_path}")
                    except Exception as e:
                        self.show_error_message(f"Error ejecutando icat: {e}")
            else:
                self.result_area.setText("Operación cancelada o inode no válido.")
        else:
            self.result_area.setText("Por favor selecciona un disco o imagen primero.")

    def get_user_input(self, prompt):
        """Abre un diálogo para obtener la entrada del usuario"""
        from PyQt5.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, 'Entrada requerida', prompt)
        return text, ok

    def show_error_message(self, message):
        """Muestra un cuadro de mensaje de error"""
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setText(message)
        msg_box.setWindowTitle("Error")
        msg_box.exec_()
