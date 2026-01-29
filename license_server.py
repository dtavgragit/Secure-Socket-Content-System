#!/usr/bin/env python3
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

HOST = "127.0.0.1"
PUERTO = 6000

# --- Cargar la clave PÚBLICA del CDM ---
with open("cdm_publica.pem", "rb") as key_file:
    pub_cdm = serialization.load_pem_public_key(key_file.read())
print("Servidor Licencias: Clave pública 'cdm_publica.pem' cargada.")

# Diccionario de claves 
claves_aes = {
    "key1": b"0123456789abcdef" 
}

def verificar_firma(pub_key, mensaje, firma):
    try:
        pub_key.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PUERTO))
s.listen(5)
print(f"Servidor de Licencias escuchando en {HOST}:{PUERTO}")

while True:
    conn, addr = s.accept()
    print(f"Conexión desde {addr}")
    try:
        datos_brutos = conn.recv(1024) 
        if b"\n" not in datos_brutos:
            conn.send(b"ERROR")
            continue

        keyid_bytes, firma = datos_brutos.split(b"\n", 1)
        keyid = keyid_bytes.decode().strip()

        if keyid not in claves_aes:
            print(f"KeyID {keyid} no encontrada.")
            conn.send(b"ERROR")
            continue

        if not verificar_firma(pub_cdm, keyid.encode(), firma):
            print("Firma inválida (CDM no verificado)")
            conn.send(b"ERROR")
            continue

        # --- CIFRADO RSA ---
        clave_aes_plana = claves_aes[keyid]
        
        # 1. Obtener números (e, n) de la clave pública
        pub_numeros = pub_cdm.public_numbers()
        e = pub_numeros.e
        n = pub_numeros.n
        
        # 2. Convertir bytes a entero
        m_int = int.from_bytes(clave_aes_plana, 'big')
        
        # 3. Cifrar: c = m^e mod n
        c_int = pow(m_int, e, n)
        
        # 4. Convertir a bytes (256 bytes para RSA 2048)
        # Esto es lo que se envía a la UA -> CDM
        clave_cifrada_bytes = c_int.to_bytes(256, 'big')
        
        conn.sendall(clave_cifrada_bytes)
        print(f"Clave enviada (cifrada con RSA) para {keyid}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()