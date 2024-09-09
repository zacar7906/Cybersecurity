#!/bin/bash
# Script para la instalación de dependencias de grado militar en Kali Linux

set -e  # Detiene la ejecución si ocurre algún error
set -u  # Trata variables no definidas como un error

echo "Iniciando instalación de dependencias de grado militar..."

# Función para registrar actividades
log_activity() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/military_grade_install.log
}

log_activity "Iniciando instalación"

# Verificar si se está ejecutando como root
if [ "$(id -u)" != "0" ]; then
   echo "Este script debe ser ejecutado como root" 1>&2
   exit 1
fi

# Actualizar el sistema
apt update && apt upgrade -y

# Herramientas avanzadas de escaneo y evaluación de vulnerabilidades
apt install -y nmap openvas nessus nikto lynis

# Herramientas de pruebas de penetración y explotación
apt install -y metasploit-framework hydra sqlmap burpsuite aircrack-ng

# Herramientas de análisis forense y recuperación de datos
apt install -y autopsy sleuthkit volatility foremost

# Herramientas de monitoreo y análisis de red
apt install -y wireshark tshark tcpdump netcat ngrep

# Herramientas de criptografía y seguridad
apt install -y john hashcat gpg

# Bibliotecas y frameworks de seguridad
pip install cryptography scapy pwntools

# Herramientas de desarrollo y análisis
pip install PyQt5 pyqtgraph matplotlib numpy scipy

# Configuración avanzada de firewall
apt install -y ufw iptables
ufw default deny incoming
ufw default allow outgoing
ufw enable

# Instalar y configurar SELinux
apt install -y selinux-basics selinux-policy-default
selinux-activate

# Instalar y configurar fail2ban
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Configurar actualizaciones automáticas de seguridad
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Instalar y configurar AIDE (Advanced Intrusion Detection Environment)
apt install -y aide
aideinit
update-aide.conf

# Añadir herramientas adicionales de seguridad avanzada
apt install -y rkhunter chkrootkit lynis auditd

# Configurar auditd
auditctl -e 1
systemctl enable auditd
systemctl start auditd

# Instalar y configurar ClamAV
apt install -y clamav clamav-daemon
freshclam
systemctl enable clamav-daemon
systemctl start clamav-daemon

# Configurar firewall avanzado con iptables
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Configurar fail2ban con reglas personalizadas
cat << EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl restart fail2ban

# Configurar contraseñas fuertes
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t10/' /etc/login.defs
sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t7/' /etc/login.defs

# Configurar GRUB con contraseña
grub-mkpasswd-pbkdf2 | tee /tmp/grub_password.txt
GRUB_PASSWORD=$(awk '/grub.pbkdf/{print$NF}' /tmp/grub_password.txt)
echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 root $GRUB_PASSWORD" >> /etc/grub.d/40_custom
update-grub

# Deshabilitar servicios innecesarios
systemctl disable bluetooth.service
systemctl disable cups.service
systemctl disable avahi-daemon.service

# Configurar límites de recursos del sistema
echo "* hard core 0" >> /etc/security/limits.conf
echo "* hard nproc 100" >> /etc/security/limits.conf
echo "* soft nproc 100" >> /etc/security/limits.conf

log_activity "Instalación completada"

echo "Instalación de dependencias de grado militar completada."
echo "Se recomienda reiniciar el sistema para aplicar todos los cambios."
echo "Por favor, revise el log en /var/log/military_grade_install.log"
