# claves_cdm.py
from cryptography.hazmat.primitives.asymmetric import rsa

# Estas son las claves del CDM
priv_cdm = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_cdm = priv_cdm.public_key()