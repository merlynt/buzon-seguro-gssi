# buzon-seguro-gssi

Herramienta criptográfica diseñada para el intercambio de documentos sensibles garantizando su confidencialidad, integridad, autenticidad y trazabilidad sobre canales públicos.

## Requisitos
* Python 3.10 o superior.

## Instalación

1. Clona este repositorio:
```bash
git clone [https://github.com/merlynt/buzon-seguro-gssi.git](https://github.com/merlynt/buzon-seguro-gssi.git)
cd buzon-seguro-gssi
```

2. Instala la biblioteca de criptografía obligatoria:
```bash
pip install -r requirements.txt
```

## Uso

La aplicación funciona mediante la línea de comandos con cinco acciones principales.

### 1. Generar identidad
Crea el par de claves X25519 (cifrado) y Ed25519 (firma) de un usuario.
```bash
python main.py generar
```

### 2. Verificar huella
Muestra la huella SHA-256 de las claves públicas para validarlas por un canal secundario.
```bash
python main.py huella
```

### 3. Cifrar y firmar
Genera el paquete seguro `.buzon` utilizando cifrado híbrido y lo firma.
```bash
python main.py cifrar
```

### 4. Descifrar y verificar
Recibe un paquete `.buzon`, verifica la firma del remitente, la integridad, y descifra el documento original.
```bash
python main.py descifrar
```

### 5. Auditar bitácora
Verifica la cadena de hashes en el registro de envíos para detectar alteraciones.
```bash
python main.py auditar
```