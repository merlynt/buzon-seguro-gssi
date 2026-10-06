import argparse
import getpass
import json
import os

from cryptography.hazmat.primitives import serialization

from crypto.funciones import (
    generar_identidad,
    huella,
    cifrar_para,
    descifrar,
    cargar_x25519_publica,
)


def comando_generar(nombre):
    """RF1: Genera las claves X25519 y Ed25519 del usuario."""

    contrasena = getpass.getpass(
        "Ingrese la contraseña para proteger las claves: "
    )

    confirmar = getpass.getpass(
        "Confirme la contraseña: "
    )

    if contrasena != confirmar:
        print("Las contraseñas no coinciden.")
        return

    try:
        generar_identidad(
            nombre,
            contrasena.encode("utf-8")
        )

        print(f"Identidad de '{nombre}' creada correctamente.")

    except Exception:
        print("No se pudo generar la identidad.")


def comando_huella(nombre):
    """RF2: Calcula y muestra la huella SHA-256 de la clave pública X25519."""

    try:
        clave = cargar_x25519_publica(nombre)

        clave_bytes = clave.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

        resultado = huella(clave_bytes)

        print(f"\nHuella X25519 de {nombre}:")
        print(resultado)

    except Exception:
        print("No se pudo obtener la huella de la clave.")


def comando_cifrar(archivo, remitente, destinatario):
    """RF3 y RF4: Cifra y firma un archivo."""

    contrasena = getpass.getpass(
        f"Ingrese la contraseña de {remitente}: "
    )

    try:
        paquete = cifrar_para(
            archivo,
            remitente,
            destinatario,
            contrasena.encode("utf-8")
        )

        nombre_archivo = os.path.basename(archivo)
        nombre_paquete = nombre_archivo + ".buzon"

        ruta_paquete = os.path.join(
            "paquetes",
            nombre_paquete
        )

        os.makedirs("paquetes", exist_ok=True)

        with open(ruta_paquete, "w", encoding="utf-8") as archivo_salida:
            json.dump(
                paquete,
                archivo_salida,
                indent=4,
                ensure_ascii=False
            )

        print("\nArchivo cifrado correctamente.")
        print(f"Paquete generado: {ruta_paquete}")

    except Exception:
        print("No se pudo cifrar el archivo.")


def comando_descifrar(paquete, destinatario):
    """RF5: Verifica la firma antes de descifrar el paquete."""

    contrasena = getpass.getpass(
        f"Ingrese la contraseña de {destinatario}: "
    )

    try:
        with open(paquete, "r", encoding="utf-8") as archivo:
            datos_paquete = json.load(archivo)

        datos_originales = descifrar(
            datos_paquete,
            destinatario,
            contrasena.encode("utf-8")
        )

        nombre_original = datos_paquete["metadatos"]["archivo"]

        nombre_salida = "descifrado_" + nombre_original

        with open(nombre_salida, "wb") as archivo_salida:
            archivo_salida.write(datos_originales)

        print("\nPaquete verificado y descifrado correctamente.")
        print(f"Archivo recuperado: {nombre_salida}")

    except Exception:
        print(
            "No se pudo verificar o descifrar el paquete."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Buzón Seguro"
    )

    subparsers = parser.add_subparsers(
        dest="accion",
        required=True
    )

    # ==========================================
    # COMANDO GENERAR
    # ==========================================

    parser_generar = subparsers.add_parser(
        "generar",
        help="Genera una nueva identidad criptográfica."
    )

    parser_generar.add_argument(
        "nombre",
        help="Nombre del usuario."
    )

    # ==========================================
    # COMANDO HUELLA
    # ==========================================

    parser_huella = subparsers.add_parser(
        "huella",
        help="Muestra la huella SHA-256 de una clave pública."
    )

    parser_huella.add_argument(
        "nombre",
        help="Nombre del usuario."
    )

    # ==========================================
    # COMANDO CIFRAR
    # ==========================================

    parser_cifrar = subparsers.add_parser(
        "cifrar",
        help="Cifra y firma un archivo."
    )

    parser_cifrar.add_argument(
        "archivo",
        help="Ruta del archivo que se desea cifrar."
    )

    parser_cifrar.add_argument(
        "remitente",
        help="Usuario que envía el archivo."
    )

    parser_cifrar.add_argument(
        "destinatario",
        help="Usuario que recibirá el archivo."
    )

    # ==========================================
    # COMANDO DESCIFRAR
    # ==========================================

    parser_descifrar = subparsers.add_parser(
        "descifrar",
        help="Verifica y descifra un paquete .buzon."
    )

    parser_descifrar.add_argument(
        "paquete",
        help="Ruta del archivo .buzon."
    )

    parser_descifrar.add_argument(
        "destinatario",
        help="Usuario que recibirá el archivo."
    )

    # ==========================================
    # COMANDO AUDITAR
    # ==========================================

    parser_auditar = subparsers.add_parser(
        "auditar",
        help="Audita la bitácora."
    )

    # ==========================================
    # PROCESAR ARGUMENTOS
    # ==========================================

    args = parser.parse_args()

    if args.accion == "generar":

        comando_generar(args.nombre)

    elif args.accion == "huella":

        comando_huella(args.nombre)

    elif args.accion == "cifrar":

        comando_cifrar(
            args.archivo,
            args.remitente,
            args.destinatario
        )

    elif args.accion == "descifrar":

        comando_descifrar(
            args.paquete,
            args.destinatario
        )

    elif args.accion == "auditar":

        print(
            "La función de auditoría corresponde al RF7 "
            "y será implementada por el integrante 3."
        )


if __name__ == "__main__":
    main()