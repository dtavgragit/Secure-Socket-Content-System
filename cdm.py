#!/usr/bin/env python3
import socket
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

HOST_CDM = "127.0.0.1"
PUERTO_CDM = 7000

# --- Cargar la clave PRIVADA del CDM ---
with open("cdm_privada.pem", "rb") as key_file:
    priv_cdm = serialization.load_pem_private_key(
        key_file.read(),
        password=None 
    )
print("CDM: Clave privada 'cdm_privada.pem' cargada.")

def aes_descifrar_ctr(clave, iv, datos):
    d = Cipher(algorithms.AES(clave), modes.CTR(iv), backend=default_backend()).decryptor()
    return d.update(datos) + d.finalize()

def firmar_mensaje(priv_key, mensaje_bytes):
    return priv_key.sign(
        mensaje_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST_CDM, PUERTO_CDM))
s.listen(1)
print(f"CDM escuchando a la UA en {HOST_CDM}:{PUERTO_CDM}")

while True:
    conn, addr = s.accept()
    try:
        datos_brutos = conn.recv(4096) 
        if not datos_brutos or b"\n" not in datos_brutos:
            conn.close()
            continue
        
        peticion_line, buffer = datos_brutos.split(b"\n", 1)
        peticion = peticion_line.decode().strip()

        if peticion.startswith("GET_REQUEST"):
            keyid = peticion.split()[1]
            print(f"CDM: UA pide firma para {keyid}")
            firma = firmar_mensaje(priv_cdm, keyid.encode())
            conn.sendall(firma)

        elif peticion.startswith("DECRYPT"):
            print("CDM: UA pide descifrar contenido")
            
            # --- Lectura robusta de datos ---
            
            # 1. Leer Clave RSA Cifrada (256 bytes para RSA-2048)
            SIZE_RSA_BLOCK = 256
            while len(buffer) < SIZE_RSA_BLOCK:
                recibido = conn.recv(SIZE_RSA_BLOCK - len(buffer))
                if not recibido: break
                buffer += recibido
            
            if len(buffer) < SIZE_RSA_BLOCK:
                print("Error: Datos insuficientes para clave RSA")
                conn.close(); continue

            clave_rsa_cifrada = buffer[:SIZE_RSA_BLOCK]
            buffer = buffer[SIZE_RSA_BLOCK:]

            # 2. Leer IV (24 bytes en Base64)
            SIZE_IV_B64 = 24
            while len(buffer) < SIZE_IV_B64:
                recibido = conn.recv(SIZE_IV_B64 - len(buffer))
                if not recibido: break
                buffer += recibido
            
            iv_b64_bytes = buffer[:SIZE_IV_B64]
            buffer = buffer[SIZE_IV_B64:]
            
            # 3. Leer Contenido Cifrado (Resto del stream)
            datos_cifrados = buffer
            while True:
                chunk = conn.recv(4096)
                if not chunk: break
                datos_cifrados += chunk
            
            # --- DESCIFRADO RSA CON POW() ---
            # m = c^d mod n
            
            c_int = int.from_bytes(clave_rsa_cifrada, 'big')
            priv_numeros = priv_cdm.private_numbers()
            d = priv_numeros.d
            n = priv_numeros.public_numbers.n
            
            m_int = pow(c_int, d, n)
            
            # Recuperar clave AES 
            # Si el número es pequeño (como nuestra clave de prueba), to_bytes funciona bien
            # Necesitamos asegurar que recuperamos el tamaño correcto.
            try:
                # Calculamos cuantos bytes necesitamos (deberían ser 16 para AES-128)
                # length = (m_int.bit_length() + 7) // 8
                clave_aes = m_int.to_bytes(16, 'big')
            except OverflowError:
                 # Fallback por si acaso el padding matemático afecta 
                 print("Error al recuperar clave AES desde RSA")
                 conn.close(); continue

            # Decodificar IV
            iv = base64.b64decode(iv_b64_bytes)

            # Descifrar contenido
            print(f"CDM: Clave recuperada exitosamente. Descifrando {len(datos_cifrados)} bytes...")
            contenido_plano = aes_descifrar_ctr(clave_aes, iv, datos_cifrados)
            
            conn.sendall(contenido_plano)
            print("CDM: Contenido enviado a UA.")

    except Exception as e:
        print(f"Error en CDM: {e}")
    finally:
        conn.close()