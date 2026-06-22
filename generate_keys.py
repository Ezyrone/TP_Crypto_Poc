import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

keys_dir = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(keys_dir, exist_ok=True)

print("Generation de la paire de cles RSA-2048...")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(os.path.join(keys_dir, "private.pem"), "wb") as f:
    f.write(private_pem)

with open(os.path.join(keys_dir, "public.pem"), "wb") as f:
    f.write(public_pem)

print("keys/private.pem")
print("keys/public.pem")
