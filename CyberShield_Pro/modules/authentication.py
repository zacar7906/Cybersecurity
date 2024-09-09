import os
import hashlib
import secrets
import re
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Optional, Tuple, Dict
import base64
import logging
from datetime import datetime, timedelta

from logging import Logger

class AutenticacionMilitar:
    def __init__(self):
        self.clave_secreta = self._generar_clave_secreta()
        self.cifrador = Fernet(self.clave_secreta)
        self.intentos_fallidos: Dict[str, Dict] = {}
        self.logger = self._configurar_logger()

    def _configurar_logger(self) -> Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('autenticacion.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        return logger

    def _generar_clave_secreta(self) -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def _derivar_clave(self, contrasena: str, sal: bytes) -> bytes:
        kdf = Scrypt(
            length=32,
            salt=sal,
            time_cost=4,
            memory_cost=65536,
            parallelism=8,
        )
        return base64.urlsafe_b64encode(kdf.derive(contrasena.encode()))

    def _hash_contrasena(self, contrasena: str) -> Tuple[str, str]:
        sal = secrets.token_bytes(32)
        clave_derivada = self._derivar_clave(contrasena, sal)
        return clave_derivada.hex(), sal.hex()

    def registrar_usuario(self, nombre_usuario: str, contrasena: str) -> str:
        if not self.es_contrasena_segura(contrasena):
            return "La contraseña no cumple con los requisitos de seguridad."
        
        contrasena_hasheada, sal = self._hash_contrasena(contrasena)
        
        # Aquí normalmente guardarías el nombre de usuario, la contraseña hasheada y la sal en una base de datos
        print(f"Usuario {nombre_usuario} registrado con éxito.")
        return "Registro exitoso"

    def es_contrasena_segura(self, contrasena: str) -> bool:
        if len(contrasena) < 16:
            return False
        
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{16,}$", contrasena):
            return False
        
        return True

    def autenticar_usuario(self, nombre_usuario: str, contrasena: str) -> bool:
        # Simular la obtención de datos del usuario desde una base de datos
        contrasena_hasheada_almacenada = "hash_almacenado"  # Esto debería obtenerse de la base de datos
        sal_almacenada = "sal_almacenada"  # Esto debería obtenerse de la base de datos

        # Verificar si el usuario ha excedido los intentos fallidos
        if self._verificar_bloqueo(nombre_usuario):
            return False

        # Derivar la clave con la sal almacenada
        clave_derivada = self._derivar_clave(contrasena, bytes.fromhex(sal_almacenada))
        
        # Comparar los hashes de forma segura
        if secrets.compare_digest(clave_derivada.hex(), contrasena_hasheada_almacenada):
            self._reiniciar_intentos(nombre_usuario)
            self.logger.info(f"Autenticación exitosa para el usuario: {nombre_usuario}")
            return True
        else:
            self._registrar_intento_fallido(nombre_usuario)
            return False

    def _verificar_bloqueo(self, nombre_usuario: str) -> bool:
        if nombre_usuario in self.intentos_fallidos:
            info = self.intentos_fallidos[nombre_usuario]
            if info['intentos'] >= 5:
                tiempo_restante = info['tiempo_bloqueo'] - datetime.now()
                if tiempo_restante > timedelta():
                    self.logger.warning(f"Intento de acceso bloqueado para el usuario: {nombre_usuario}. Tiempo restante: {tiempo_restante}")
                    return True
                else:
                    del self.intentos_fallidos[nombre_usuario]
        return False

    def _registrar_intento_fallido(self, nombre_usuario: str) -> None:
        if nombre_usuario not in self.intentos_fallidos:
            self.intentos_fallidos[nombre_usuario] = {'intentos': 1, 'tiempo_bloqueo': None}
        else:
            self.intentos_fallidos[nombre_usuario]['intentos'] += 1
        
        intentos = self.intentos_fallidos[nombre_usuario]['intentos']
        if intentos >= 5:
            tiempo_bloqueo = datetime.now() + timedelta(minutes=5 * (2 ** (intentos - 5)))
            self.intentos_fallidos[nombre_usuario]['tiempo_bloqueo'] = tiempo_bloqueo
        
        self.logger.warning(f"Intento de autenticación fallido para el usuario: {nombre_usuario}. Intentos: {intentos}")
        time.sleep(2 ** intentos)  # Retraso exponencial

    def _reiniciar_intentos(self, nombre_usuario: str) -> None:
        if nombre_usuario in self.intentos_fallidos:
            del self.intentos_fallidos[nombre_usuario]

    def cifrar_datos(self, datos: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.cifrador.encrypt(nonce + datos.encode())

    def descifrar_datos(self, datos_cifrados: bytes) -> Optional[str]:
        try:
            nonce = datos_cifrados[:12]
            datos = self.cifrador.decrypt(datos_cifrados[12:])
            if datos[:12] != nonce:
                raise ValueError("Nonce no coincide")
            return datos[12:].decode()
        except Exception as e:
            print(f"Error al descifrar: {e}")
            return None

    def rotar_clave(self) -> None:
        nueva_clave = self._generar_clave_secreta()
        nuevo_cifrador = Fernet(nueva_clave)
        
        # Recorrer la base de datos y actualizar todos los campos cifrados
        try:
            conexion = obtener_conexion_bd()  # Función hipotética para obtener la conexión a la BD
            cursor = conexion.cursor()
            
            # Obtener todos los registros con campos cifrados
            cursor.execute("SELECT id, campo_cifrado FROM tabla_con_datos_cifrados")
            registros = cursor.fetchall()
            
            for id_registro, campo_cifrado in registros:
                # Descifrar con la clave antigua
                datos_descifrados = self.descifrar_datos(campo_cifrado)
                
                if datos_descifrados:
                    # Cifrar con la nueva clave
                    nuevos_datos_cifrados = nuevo_cifrador.encrypt(datos_descifrados.encode())
                    
                    # Actualizar el registro en la base de datos
                    cursor.execute("UPDATE tabla_con_datos_cifrados SET campo_cifrado = ? WHERE id = ?",
                                   (nuevos_datos_cifrados, id_registro))
            
            conexion.commit()
            self.logger.info(f"Se han actualizado {len(registros)} registros con la nueva clave de cifrado")
        except Exception as e:
            self.logger.error(f"Error al rotar la clave: {e}")
            conexion.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if conexion:
                conexion.close()
        
        self.clave_secreta = nueva_clave
        self.cifrador = nuevo_cifrador
        self.logger.info("Clave de cifrado rotada exitosamente")

# Configuración de variables de entorno para mayor seguridad
os.environ['PYTHONHASHSEED'] = str(secrets.randbits(128))

# Ejemplo de uso
auth = AutenticacionMilitar()
resultado = auth.registrar_usuario("usuario123", "ContraseñaMuySegura2024!")
print(resultado)
