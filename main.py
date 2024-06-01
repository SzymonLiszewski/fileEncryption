import base64

from symmetric import encrypt_file, encrypt_bmp, exclude_metadata, decrypt_bmp, decrypt_file
from asymmetric import generate_asymmetric_keys,encrypt_symmetric_key
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def encrypt(input_file_path, output_file_path, asymmetric_public_key, algorithm='AES', mode='CBC',asymetric_algorithm='RSA'):
    if algorithm == 'AES':
        key = os.urandom(32)  # 256-bitowy klucz AES
    elif algorithm == '3DES':
        key = os.urandom(24)  # 192-bitowy klucz 3DES
    file_extension = os.path.splitext(input_file_path)[1]
    if file_extension.lower() == '.bmp':
        encrypt_bmp(input_file_path,"test_"+output_file_path,key, asymmetric_public_key,asymetric_algorithm,algorithm,mode)
        exclude_metadata("test_"+output_file_path)
    encrypt_file(input_file_path,output_file_path,key, asymmetric_public_key,asymetric_algorithm,algorithm,mode)

def decrypt(input_file_path, output_file_path, private_key):
    metadata = exclude_metadata(input_file_path)
    symmetric_algorithm = metadata['symmetric_algorithm']
    algorithm_mode = metadata['mode']
    asymmetric_algorithm = metadata['asymmetric_encryption_algorithm']
    encrypted_symmetric_key = base64.b64decode(metadata['encrypted_symmetric_key'])
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypt_file(input_file_path, output_file_path, symmetric_key, symmetric_algorithm, algorithm_mode)

#przyklad
private_key, public_key = generate_asymmetric_keys('rsa') #do wyboru rsa/ecc
encrypt('tux.bmp', 'encrypted_aes_cbc.bmp', public_key, algorithm='AES', mode='CBC',asymetric_algorithm='rsa') #algorithm AES albo 3DES, mode CBC albo ECB
decrypt('encrypted_aes_cbc.bmp', 'decrypted.bmp', private_key)