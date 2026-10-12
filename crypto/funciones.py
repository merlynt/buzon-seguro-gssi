import os
import json
import base64
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CLAVES_PRIVADAS = os.path.join(BASE_DIR, "claves", "privadas")
CLAVES_PUBLICAS = os.path.join(BASE_DIR, "claves", "publicas")
PAQUETES_DIR = os.path.join(BASE_DIR, "paquetes")

BITACORA_FILE = os.path.join(BASE_DIR, "bitacora.log")


def crear_directorios():
    """Crea los directorios necesarios para almacenar las claves y paquetes."""
    os.makedirs(CLAVES_PRIVADAS, exist_ok=True)
    os.makedirs(CLAVES_PUBLICAS, exist_ok=True)
    os.makedirs(PAQUETES_DIR, exist_ok=True)

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("utf-8")


def de_b64(x: str) -> bytes:
    return base64.b64decode(x.encode("utf-8"))

def generar_identidad(nombre: str, contrasena: bytes) -> None:
    """
    RF1:
    Genera una identidad compuesta por:
    - Par X25519 para acuerdo de claves.
    - Par Ed25519 para firma digital.

    Las claves privadas se almacenan cifradas con contraseña.
    Las claves públicas se almacenan en formato binario.
    """

    crear_directorios()

    # ==============================
    # 1. Generar claves X25519
    # ==============================

    x25519_privada = x25519.X25519PrivateKey.generate()
    x25519_publica = x25519_privada.public_key()

    # ==============================
    # 2. Generar claves Ed25519
    # ==============================

    ed25519_privada = ed25519.Ed25519PrivateKey.generate()
    ed25519_publica = ed25519_privada.public_key()

    # ==============================
    # 3. Serializar X25519 privada
    # ==============================

    x25519_privada_bytes = x25519_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(contrasena)
    )

    # ==============================
    # 4. Serializar Ed25519 privada
    # ==============================

    ed25519_privada_bytes = ed25519_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(contrasena)
    )

    # ==============================
    # 5. Serializar X25519 pública
    # ==============================

    x25519_publica_bytes = x25519_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # ==============================
    # 6. Serializar Ed25519 pública
    # ==============================

    ed25519_publica_bytes = ed25519_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # ==============================
    # 7. Guardar claves
    # ==============================

    ruta_x_privada = os.path.join(
        CLAVES_PRIVADAS,
        f"{nombre}_x25519_private.pem"
    )

    ruta_ed_privada = os.path.join(
        CLAVES_PRIVADAS,
        f"{nombre}_ed25519_private.pem"
    )

    ruta_x_publica = os.path.join(
        CLAVES_PUBLICAS,
        f"{nombre}_x25519_public.bin"
    )

    ruta_ed_publica = os.path.join(
        CLAVES_PUBLICAS,
        f"{nombre}_ed25519_public.bin"
    )

    with open(ruta_x_privada, "wb") as archivo:
        archivo.write(x25519_privada_bytes)

    with open(ruta_ed_privada, "wb") as archivo:
        archivo.write(ed25519_privada_bytes)

    with open(ruta_x_publica, "wb") as archivo:
        archivo.write(x25519_publica_bytes)

    with open(ruta_ed_publica, "wb") as archivo:
        archivo.write(ed25519_publica_bytes)

    print(f"Identidad de '{nombre}' generada correctamente.")

def huella(clave_publica_bytes: bytes) -> str:
    """
    RF2:
    Calcula la huella SHA-256 de una clave pública.
    """

    return hashlib.sha256(clave_publica_bytes).hexdigest()

def cargar_x25519_privada(nombre: str, contrasena: bytes):
    ruta = os.path.join(
        CLAVES_PRIVADAS,
        f"{nombre}_x25519_private.pem"
    )

    with open(ruta, "rb") as archivo:
        datos = archivo.read()

    return serialization.load_pem_private_key(
        datos,
        password=contrasena
    )


def cargar_ed25519_privada(nombre: str, contrasena: bytes):
    ruta = os.path.join(
        CLAVES_PRIVADAS,
        f"{nombre}_ed25519_private.pem"
    )

    with open(ruta, "rb") as archivo:
        datos = archivo.read()

    return serialization.load_pem_private_key(
        datos,
        password=contrasena
    )


def cargar_x25519_publica(nombre: str):
    ruta = os.path.join(
        CLAVES_PUBLICAS,
        f"{nombre}_x25519_public.bin"
    )

    with open(ruta, "rb") as archivo:
        datos = archivo.read()

    return x25519.X25519PublicKey.from_public_bytes(datos)


def cargar_ed25519_publica(nombre: str):
    ruta = os.path.join(
        CLAVES_PUBLICAS,
        f"{nombre}_ed25519_public.bin"
    )

    with open(ruta, "rb") as archivo:
        datos = archivo.read()

    return ed25519.Ed25519PublicKey.from_public_bytes(datos)

def cifrar_para(
    ruta_archivo: str,
    remitente: str,
    destinatario: str,
    contrasena: bytes
) -> dict:
    """
    RF3 y RF4:
    Cifra un documento para un destinatario usando:

    X25519 efímero
    ECDH
    HKDF-SHA256
    AES-256-GCM

    Posteriormente firma el paquete con Ed25519.
    """

    # ==============================
    # 1. Leer documento original
    # ==============================

    with open(ruta_archivo, "rb") as archivo:
        datos_archivo = archivo.read()

    # ==============================
    # 2. Calcular SHA-256 original
    # ==============================

    hash_original = hashlib.sha256(datos_archivo).hexdigest()

    # ==============================
    # 3. Obtener clave pública X25519
    #    del destinatario
    # ==============================

    destinatario_publica = cargar_x25519_publica(destinatario)

    # ==============================
    # 4. Generar clave efímera
    # ==============================

    efimera_privada = x25519.X25519PrivateKey.generate()
    efimera_publica = efimera_privada.public_key()

    # ==============================
    # 5. Obtener secreto ECDH
    # ==============================

    secreto_compartido = efimera_privada.exchange(
        destinatario_publica
    )

    # ==============================
    # 6. Derivar clave con HKDF
    # ==============================

    clave = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"buzon-seguro-v1"
    ).derive(secreto_compartido)

    # ==============================
    # 7. Crear contenido
    # ==============================

    contenido = {
        "sha256_original": hash_original,
        "datos": b64(datos_archivo)
    }

    contenido_bytes = json.dumps(
        contenido,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    # ==============================
    # 8. Crear metadatos
    # ==============================

    metadatos = {
        "remitente": remitente,
        "destinatario": destinatario,
        "fecha": datetime.now(timezone.utc).isoformat(),
        "archivo": os.path.basename(ruta_archivo)
    }

    # ==============================
    # 9. Serializar metadatos
    # ==============================

    metadatos_bytes = json.dumps(
        metadatos,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    # ==============================
    # 10. Crear nonce
    # ==============================

    nonce = os.urandom(12)

    # ==============================
    # 11. Cifrar con AES-256-GCM
    # ==============================

    aes = AESGCM(clave)

    cifrado = aes.encrypt(
        nonce,
        contenido_bytes,
        metadatos_bytes
    )

    # ==============================
    # 12. Obtener clave pública
    #     efímera en bytes
    # ==============================

    efimera_publica_bytes = efimera_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # ==============================
    # 13. Construir datos a firmar
    # ==============================

    datos_firma = (
        efimera_publica_bytes
        + nonce
        + metadatos_bytes
        + cifrado
    )

    # ==============================
    # 14. Cargar privada Ed25519
    #     del remitente
    # ==============================

    privada_firma = cargar_ed25519_privada(
        remitente,
        contrasena
    )

    # ==============================
    # 15. Firmar
    # ==============================

    firma = privada_firma.sign(datos_firma)

    # ==============================
    # 16. Construir paquete
    # ==============================

    paquete = {
        "version": "buzon-seguro-v1",
        "metadatos": metadatos,
        "efimera_pub": b64(efimera_publica_bytes),
        "nonce": b64(nonce),
        "cifrado": b64(cifrado),
        "firma": b64(firma)
    }

    return paquete

def descifrar(
    paquete: dict,
    destinatario: str,
    contrasena: bytes
) -> bytes:
    """
    RF5:
    Verifica primero la firma del remitente.
    Después deriva la clave y descifra el contenido.
    """

    try:
        # ==============================
        # 1. Obtener metadatos
        # ==============================

        metadatos = paquete["metadatos"]

        remitente = metadatos["remitente"]

        # Comprobar que el paquete está dirigido
        # al usuario que intenta descifrarlo.
        if metadatos["destinatario"] != destinatario:
            raise ValueError("Paquete no destinado al usuario.")

        # ==============================
        # 2. Decodificar datos
        # ==============================

        efimera_publica_bytes = de_b64(
            paquete["efimera_pub"]
        )

        nonce = de_b64(
            paquete["nonce"]
        )

        cifrado = de_b64(
            paquete["cifrado"]
        )

        firma = de_b64(
            paquete["firma"]
        )

        # ==============================
        # 3. Serializar metadatos
        # ==============================

        metadatos_bytes = json.dumps(
            metadatos,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        # ==============================
        # 4. Construir exactamente
        #    los datos firmados
        # ==============================

        datos_firma = (
            efimera_publica_bytes
            + nonce
            + metadatos_bytes
            + cifrado
        )

        # ==============================
        # 5. Obtener clave pública
        #    Ed25519 del remitente
        # ==============================

        publica_remitente = cargar_ed25519_publica(
            remitente
        )

        # ==============================
        # 6. VERIFICAR FIRMA PRIMERO
        # ==============================

        publica_remitente.verify(
            firma,
            datos_firma
        )

        # ==============================
        # 7. Cargar privada X25519
        #    del destinatario
        # ==============================

        privada_destinatario = cargar_x25519_privada(
            destinatario,
            contrasena
        )

        # ==============================
        # 8. Recuperar clave efímera
        # ==============================

        efimera_publica = x25519.X25519PublicKey.from_public_bytes(
            efimera_publica_bytes
        )

        # ==============================
        # 9. ECDH
        # ==============================

        secreto_compartido = privada_destinatario.exchange(
            efimera_publica
        )

        # ==============================
        # 10. HKDF
        # ==============================

        clave = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"buzon-seguro-v1"
        ).derive(secreto_compartido)

        # ==============================
        # 11. Descifrar AES-GCM
        # ==============================

        aes = AESGCM(clave)

        contenido_bytes = aes.decrypt(
            nonce,
            cifrado,
            metadatos_bytes
        )

        # ==============================
        # 12. Obtener contenido
        # ==============================

        contenido = json.loads(
            contenido_bytes.decode("utf-8")
        )

        # ==============================
        # 13. Recuperar documento
        # ==============================

        datos_archivo = de_b64(
            contenido["datos"]
        )

        # ==============================
        # 14. Verificar hash original
        # ==============================

        hash_calculado = hashlib.sha256(
            datos_archivo
        ).hexdigest()

        if hash_calculado != contenido["sha256_original"]:
            raise ValueError(
                "La integridad del archivo no coincide."
            )

        return datos_archivo

    except Exception:
        raise ValueError(
            "No se pudo verificar o descifrar el paquete."
        )

# ==========================================
# RF7: SISTEMA DE BITÁCORA DE AUDITORÍA
# ==========================================

def registrar_bitacora(operacion: str, usuario: str, archivo: str) -> None:
    """RF7: Registra un evento en la bitácora encadenada."""
    hash_previo = "0" * 64  # Hash inicial por defecto si está vacía
    
    if os.path.exists(BITACORA_FILE):
        with open(BITACORA_FILE, "rb") as f:
            lineas = f.readlines()
            if lineas:
                ultima_linea = lineas[-1]
                hash_previo = hashlib.sha256(ultima_linea).hexdigest()
                
    registro = {
        "fecha": datetime.now(timezone.utc).isoformat(),
        "operacion": operacion,
        "usuario": usuario,
        "archivo": archivo,
        "hash_previo": hash_previo
    }
    
    linea_str = json.dumps(registro, sort_keys=True) + "\n"
    
    with open(BITACORA_FILE, "a", encoding="utf-8") as f:
        f.write(linea_str)

def auditar_bitacora() -> tuple:
    """RF7: Audita la cadena de hashes de la bitácora."""
    if not os.path.exists(BITACORA_FILE):
        return True, "No hay bitácora para auditar."
        
    with open(BITACORA_FILE, "rb") as f:
        lineas = f.readlines()
        
    hash_esperado = "0" * 64
    for i, linea_bytes in enumerate(lineas, start=1):
        registro = json.loads(linea_bytes.decode("utf-8"))
        if registro["hash_previo"] != hash_esperado:
            return False, f"¡ALTERACIÓN DETECTADA! La línea {i} fue modificada. La cadena está rota."
        
        hash_esperado = hashlib.sha256(linea_bytes).hexdigest()
        
    return True, f"La bitácora está íntegra. Se auditaron {len(lineas)} registros."