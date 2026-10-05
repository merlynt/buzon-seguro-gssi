import os, json, base64, hashlib, argparse
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def generar_identidad(nombre: str, contrasena: bytes) -> None:
    """RF1: crea un par X25519 (cifrado) y un par Ed25519 (firma).
    Guarda las claves privadas cifradas con la contraseña y publica las públicas."""
    raise NotImplementedError 

def huella(clave_publica_bytes: bytes) -> str:
    """RF2: huella SHA-256 de una clave pública, para verificarla por otro canal."""
    raise NotImplementedError 

def cifrar_para(ruta_archivo: str, remitente: str, destinatario: str, contrasena: bytes) -> dict:
    """RF3 y RF4: ECDH efímero + HKDF + AES-256-GCM, y firma Ed25519 del remitente.
    Devuelve el paquete (ver formato en el Anexo B)."""
    raise NotImplementedError 

def descifrar(paquete: dict, destinatario: str, contrasena: bytes) -> bytes:
    """RF5: verifica la firma ANTES de descifrar; si algo falla, rechaza sin revelar detalles."""
    raise NotImplementedError

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Buzón Seguro")
    p.add_argument("accion", choices=["generar", "huella", "cifrar", "descifrar", "auditar"])
    
    args = p.parse_args()