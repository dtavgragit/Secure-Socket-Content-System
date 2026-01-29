#!/usr/bin/env python3
import socket

HOST_CONTENIDOS = "127.0.0.1"
PUERTO_CONTENIDOS = 5000
HOST_LICENCIAS = "127.0.0.1"
PUERTO_LICENCIAS = 6000
HOST_CDM = "127.0.0.1"
PUERTO_CDM = 7000

# --- Funciones de red (UA) ---

def listar():
    s = socket.socket()
    s.connect((HOST_CONTENIDOS, PUERTO_CONTENIDOS))
    s.sendall(b"LIST\n")
    datos = s.recv(4096)
    s.close()
    return datos.decode().strip().splitlines()

def obtener_archivo(nombre):
    s = socket.socket()
    s.connect((HOST_CONTENIDOS, PUERTO_CONTENIDOS))
    s.sendall(f"GET {nombre}\n".encode())
    recibido = b""
    while b"<END_MANIFEST>\n" not in recibido:
        recibido += s.recv(1024)
    manifiesto, resto = recibido.split(b"<END_MANIFEST>\n", 1)
    
    # Seguir leyendo si falta contenido
    s.settimeout(2.0)
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk: break
            resto += chunk
    except socket.timeout:
        pass
    s.close()
    
    info = {}
    for linea in manifiesto.decode().splitlines():
        if ":" in linea:
            k,v = linea.split(":",1)
            info[k.strip()] = v.strip()
    return info, resto

# Paso 2: UA pide al CDM que genere la solicitud
def pedir_firma_al_cdm(keyid):
    s = socket.socket()
    s.connect((HOST_CDM, PUERTO_CDM))
    s.sendall(f"GET_REQUEST {keyid}\n".encode())
    firma = s.recv(512)
    s.close()
    return firma

# Paso 3: UA reenvía la solicitud firmada al Servidor de Licencias
def pedir_licencia_al_servidor(keyid, firma):
    s = socket.socket()
    s.connect((HOST_LICENCIAS, PUERTO_LICENCIAS))
    s.sendall(keyid.encode() + b"\n") 
    s.sendall(firma)
    # Recibimos la clave cifrada RSA
    clave_cifrada = s.recv(4096) 
    s.close()
    if clave_cifrada == b"ERROR":
        print("❌ Servidor de Licencias rechazó la solicitud")
        return None
    return clave_cifrada

# Paso 4: UA envía la licencia (cifrada) y el contenido al CDM
def pedir_descifrado_al_cdm(clave_cifrada_rsa, iv_b64, datos_cifrados):
    s = socket.socket()
    s.connect((HOST_CDM, PUERTO_CDM))
    
    # 1. Enviar cabecera y datos
    s.sendall(b"DECRYPT\n")
    s.sendall(clave_cifrada_rsa)
    s.sendall(iv_b64.encode())
    s.sendall(datos_cifrados)
    
    # 2. Cerrar escritura para indicar fin de envío
    s.shutdown(socket.SHUT_WR) 

    # 3. Leer respuesta
    datos_descifrados = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        datos_descifrados += chunk
    s.close()
    return datos_descifrados

def main():
    print("📄 Contenidos disponibles:")
    try:
        archivos = listar()
    except ConnectionRefusedError:
        print("❌ No se pudo conectar al Servidor de Contenidos. ¿Está encendido?")
        return

    for a in archivos:
        print(" -", a)

    nombre = input("\n👉 Escribe el nombre del archivo que quieres: ")
    if not nombre: return

    try:
        manifiesto, datos_cifrados = obtener_archivo(nombre)
    except Exception as e:
        print(f"❌ Error obteniendo archivo: {e}")
        return

    print("\n🧾 Manifiesto recibido:")
    for k,v in manifiesto.items():
        print(f"{k}: {v}")

    if manifiesto.get("encrypted") == "yes":
        keyid = manifiesto["keyid"]
        iv_b64 = manifiesto["iv"]
        
        print("\n🔐 UA: Pidiendo firma al CDM...")
        firma = pedir_firma_al_cdm(keyid)
        
        print("🔐 UA: Pidiendo licencia al Servidor...")
        clave_rsa_blob = pedir_licencia_al_servidor(keyid, firma)
        
        if clave_rsa_blob is None:
            return
            
        print("🔐 UA: Enviando licencia cifrada y contenido al CDM...")
        # Aquí definimos la variable 'descifrado'
        descifrado = pedir_descifrado_al_cdm(clave_rsa_blob, iv_b64, datos_cifrados)

        print("\n📜 Primeros bytes del contenido descifrado (recibido del CDM):")
        
        # Aquí USAMOS la variable 'descifrado', por lo que el aviso debería desaparecer
        if not descifrado:
            print("⚠️ El CDM no devolvió datos (¿error de descifrado?)")
        else:
            try:
                print(descifrado.decode())
            except UnicodeDecodeError:
                # Si es una imagen o binario, mostramos representación
                print(f"[Datos binarios: {len(descifrado)} bytes]")
                print(descifrado[:200]) # Mostramos el inicio en raw
    else:
        print("\n📜 Contenido sin cifrar:")
        print(datos_cifrados.decode(errors="ignore"))

if __name__ == "__main__":
    main()