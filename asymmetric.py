import os

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_asymmetric_keys(algorithm):
    if algorithm.lower() == 'rsa':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    elif algorithm.lower() == 'ecc':
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_private_key, pem_public_key
    else:
        raise ValueError("Unsupported algorithm. Choose either 'rsa', 'dsa', or 'ecc'.")

    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(symmetric_key, public_key, algorithm):
    if algorithm.lower() == 'rsa':
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    elif algorithm.lower() == 'ecc':
        public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())
        encrypted_symmetric_key = public_key_obj.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_symmetric_key
    else:
        raise ValueError("Unsupported algorithm. Choose either 'rsa', 'dsa', or 'ecc'.")
    return encrypted_symmetric_key