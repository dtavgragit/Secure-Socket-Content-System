#!/usr/bin/env python3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

print("Generando nuevo par de claves para el CDM...")

# 1. Generar claves
priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_key = priv_key.public_key()

# 2. Serializar (guardar) clave privada
pem_priv = priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() # Sin contraseña para este proyecto
)
with open("cdm_privada.pem", "wb") as f:
    f.write(pem_priv)

# 3. Serializar (guardar) clave pública
pem_pub = pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("cdm_publica.pem", "wb") as f:
    f.write(pem_pub)

print("✅ Claves 'cdm_privada.pem' y 'cdm_publica.pem' generadas.")