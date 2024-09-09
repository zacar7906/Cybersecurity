import logging
from typing import List, Dict, Tuple
from scapy.all import sniff, IP, TCP, UDP
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import json
import re

class IntrusionDetectionSystem:
    def __init__(self, rules_file: str, log_file: str, password: str):
        self.rules = self._load_rules(rules_file, password)
        self.logger = self._setup_logger(log_file)
        self.encryption_key = self._generate_key(password)
        self.cipher_suite = Fernet(self.encryption_key)
        self.packet_buffer = []
        self.buffer_size = 1000

    def _generate_key(self, password: str) -> bytes:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _load_rules(self, rules_file: str, password: str) -> Dict[str, List[Dict[str, str]]]:
        with open(rules_file, 'rb') as f:
            encrypted_data = f.read()
        
        temp_cipher = Fernet(self._generate_key(password))
        decrypted_data = temp_cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data)

    def _setup_logger(self, log_file: str) -> logging.Logger:
        logger = logging.getLogger('IDS')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(log_file, mode='a')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        return logger

    def _encrypt_log(self, message: str) -> bytes:
        return self.cipher_suite.encrypt(message.encode())

    def _decrypt_log(self, encrypted_message: bytes) -> str:
        return self.cipher_suite.decrypt(encrypted_message).decode()

    def analyze_packet(self, packet):
        self.packet_buffer.append(packet)
        
        if len(self.packet_buffer) >= self.buffer_size:
            self._analyze_buffer()

    def _analyze_buffer(self):
        for packet in self.packet_buffer:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    self._analyze_tcp_packet(packet, src_ip, dst_ip)
                elif UDP in packet:
                    self._analyze_udp_packet(packet, src_ip, dst_ip)

        self.packet_buffer.clear()

    def _analyze_tcp_packet(self, packet, src_ip: str, dst_ip: str):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = str(packet[TCP].payload)

        for rule_name, rule_patterns in self.rules.items():
            if self._match_rule(src_ip, dst_ip, src_port, dst_port, payload, rule_patterns):
                self._log_alert(rule_name, src_ip, src_port, dst_ip, dst_port)

    def _analyze_udp_packet(self, packet, src_ip: str, dst_ip: str):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload = str(packet[UDP].payload)

        for rule_name, rule_patterns in self.rules.items():
            if self._match_rule(src_ip, dst_ip, src_port, dst_port, payload, rule_patterns):
                self._log_alert(rule_name, src_ip, src_port, dst_ip, dst_port)

    def _match_rule(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: str, patterns: List[Dict[str, str]]) -> bool:
        for pattern in patterns:
            if (
                self._match_ip(pattern.get('src_ip'), src_ip) and
                self._match_ip(pattern.get('dst_ip'), dst_ip) and
                self._match_port(pattern.get('src_port'), src_port) and
                self._match_port(pattern.get('dst_port'), dst_port) and
                self._match_payload(pattern.get('payload'), payload)
            ):
                return True
        return False

    def _match_ip(self, pattern: str, ip: str) -> bool:
        return pattern is None or re.match(pattern, ip)

    def _match_port(self, pattern: str, port: int) -> bool:
        return pattern is None or int(pattern) == port

    def _match_payload(self, pattern: str, payload: str) -> bool:
        return pattern is None or re.search(pattern, payload)

    def _log_alert(self, rule_name: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        message = f"Alerta: {rule_name} detectada - {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        encrypted_log = self._encrypt_log(message)
        self.logger.warning(encrypted_log)

    def start_monitoring(self, interface: str):
        print(f"Iniciando monitoreo en la interfaz {interface}...")
        sniff(iface=interface, prn=self.analyze_packet, store=0)

if __name__ == "__main__":
    import getpass
    password = getpass.getpass("Ingrese la contraseña para desencriptar las reglas: ")
    ids = IntrusionDetectionSystem("rules.enc", "ids_log.enc", password)
    ids.start_monitoring("eth0")
