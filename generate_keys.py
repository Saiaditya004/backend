# generate_keys.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

os.makedirs("keys", exist_ok=True)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
with open("keys/private_key.pem", "wb") as f:
    f.write(priv_pem)

pub_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("keys/public_key.pem", "wb") as f:
    f.write(pub_pem)

print("Keys generated: keys/private_key.pem, keys/public_key.pem")
