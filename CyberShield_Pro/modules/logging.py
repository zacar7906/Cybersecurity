import logging
import os
from datetime import datetime

class MilitaryLogger:
    def __init__(self, log_file="military_operations.log"):
        self.logger = logging.getLogger("MilitaryLogger")
        self.logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] - %(message)s")
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def log_mission(self, mission_code, details):
        self.logger.info(f"MISIÓN {mission_code}: {details}")
    
    def log_intel(self, source, information):
        self.logger.debug(f"INTELIGENCIA de {source}: {information}")
    
    def log_alert(self, threat_level, message):
        self.logger.warning(f"ALERTA NIVEL {threat_level}: {message}")
    
    def log_critical(self, situation):
        self.logger.critical(f"SITUACIÓN CRÍTICA: {situation}")

# Uso del logger
if __name__ == "__main__":
    military_logger = MilitaryLogger()
    
    military_logger.log_mission("ALFA-1", "Reconocimiento en sector 7")
    military_logger.log_intel("Satélite", "Movimiento de tropas enemigas en coordenadas X")
    military_logger.log_alert("BRAVO", "Posible infiltración en perímetro sur")
    military_logger.log_critical("Ataque inminente detectado")
