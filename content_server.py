#!/usr/bin/env python3
"""
Servidor de Contenidos - Parte II
-------------------------------
Envía archivos cifrados o planos al cliente.
Aplica marca de agua visible a imágenes.
"""
import socket
import os
import base64
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = "127.0.0.1"
PUERTO = 5000
CARPETA = "archivos"

# Crear carpeta si no existe
if not os.path.exists(CARPETA):
    os.makedirs(CARPETA)
    print(f"📂 Carpeta '{CARPETA}' creada automáticamente.")

# ====== Funciones de ayuda ======
def aes_cifrar_ctr(clave, iv, datos):
    c = Cipher(algorithms.AES(clave), modes.CTR(iv), backend=default_backend()).encryptor()
    return c.update(datos) + c.finalize()

def aplicar_marca_agua(imagen_path, usuario_id):
    """Aplica marca de agua visible a la imagen y devuelve path temporal"""
    imagen = Image.open(imagen_path).convert("RGBA")
    txt = Image.new("RGBA", imagen.size, (255,255,255,0))
    draw = ImageDraw.Draw(txt)
    font = ImageFont.load_default()
    draw.text((10, 10), f"Usuario: {usuario_id}", fill=(255,0,0,128), font=font)
    watermarked = Image.alpha_composite(imagen, txt)
    salida_path = "imagen_marca.png"
    watermarked.save(salida_path)
    return salida_path

# ====== Servidor ======
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PUERTO))
s.listen(5)
print(f"Servidor de Contenidos escuchando en {HOST}:{PUERTO}")

while True:
    conn, addr = s.accept()
    print(f"Conexión desde {addr}")
    try:
        cmd = conn.recv(1024).decode().strip()
        if cmd.startswith("LIST"):
            archivos = os.listdir(CARPETA)
            # Filtrar por extensión si se indica
            partes = cmd.split()
            if len(partes) == 2:
                ext = partes[1]
                archivos = [f for f in archivos if f.endswith(ext)]
            conn.sendall("\n".join(archivos).encode())

        elif cmd.startswith("GET"):
            nombre = cmd.split()[1]
            path = os.path.join(CARPETA, nombre)
            if not os.path.exists(path):
                conn.sendall(b"ERROR: archivo no encontrado")
                continue

            # Preparar manifiesto
            manifiesto = {}
            cifrado = nombre.endswith("_cifrado.txt")
            manifiesto["encrypted"] = "yes" if cifrado else "no"
            manifiesto["mode"] = "CTR"
            manifiesto["license_url"] = "http://127.0.0.1:6000"
            manifiesto["keyid"] = "key1"
            iv = os.urandom(16)
            manifiesto["iv"] = base64.b64encode(iv).decode()

            # Aplicar marca de agua si es imagen
            if nombre.endswith((".png", ".jpg", ".jpeg")):
                path = aplicar_marca_agua(path, "ejemplo_usuario")

            with open(path, "rb") as f:
                datos = f.read()
            if cifrado:
                clave = b"0123456789abcdef"  # AES-128 de prueba
                datos = aes_cifrar_ctr(clave, iv, datos)

            # Enviar manifiesto
            m = "\n".join([f"{k}: {v}" for k,v in manifiesto.items()]).encode()
            conn.sendall(m + b"\n<END_MANIFEST>\n")
            # Enviar datos
            conn.sendall(datos)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
