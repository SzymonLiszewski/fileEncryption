import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import json
from asymmetric import encrypt_symmetric_key

def add_metadata_to_encrypted_file(output_file_path, symmetric_iv, symmetric_encrypted_key, symmetric_algorithm='AES', asymmetric_algorithm='RSA', mode='CBC'):
    # Tworzenie metadanych
    metadata = {
        'symmetric_algorithm': symmetric_algorithm,
        'asymmetric_encryption_algorithm': asymmetric_algorithm,
        'mode': mode,
        #'symmetric_iv': symmetric_iv.decode('utf-8'),  # Dekodowanie IV do stringa
        'encrypted_symmetric_key': base64.b64encode(symmetric_encrypted_key).decode('utf-8')  # Dekodowanie zaszyfrowanego klucza asymetrycznego do stringa
    }

    # Zapisanie metadanych i zaszyfrowanych danych do pliku
    with open(output_file_path, 'wb') as f:
        f.write(json.dumps(metadata).encode('utf-8'))  # Zapisanie metadanych jako JSON
        f.write(b'\n')  # Dodanie nowej linii jako separatora

def encrypt_file(input_file_path, output_file_path, key, asymmetric_public_key, asymmetric_algorithm='rsa', algorithm='AES', mode='CBC'):
    # Wczytanie pliku
    with open(input_file_path, 'rb') as f:
        file_data = f.read()

    # Dodanie paddingu do danych
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Inicjalizacja wektora IV
    iv = os.urandom(8 if algorithm == '3DES' else 16) if mode != 'ECB' else None

    # Wybór algorytmu szyfrowania i trybu
    if algorithm == 'AES':
        cipher_algorithm = algorithms.AES(key)
    elif algorithm == '3DES':
        cipher_algorithm = algorithms.TripleDES(key)
    else:
        raise ValueError("Unsupported algorithm. Choose either 'AES' or '3DES'.")

    if mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'ECB':
        cipher_mode = modes.ECB()
    else:
        raise ValueError("Unsupported mode. Choose either 'CBC' or 'ECB'.")

    # Inicjalizacja szyfru
    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    # Szyfrowanie danych
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # dodanie metadanych do pliku wyjsciowego
    key = encrypt_symmetric_key(key, asymmetric_public_key, asymmetric_algorithm)
    add_metadata_to_encrypted_file(output_file_path, iv, key, symmetric_algorithm=algorithm,mode=mode)

    # Zapisanie zaszyfrowanego pliku
    with open(output_file_path, 'ab') as f:
        if iv:  # Zapisanie wektora IV jeśli istnieje
            f.write(iv)
        f.write(encrypted_data)

def decrypt_file(input_file_path, output_file_path, key, algorithm='AES', mode='CBC'):
    IV_SIZE = 8 if algorithm == '3DES' else 16

    # Wczytanie zaszyfrowanego pliku
    with open(input_file_path, 'rb') as f:
        iv = f.read(IV_SIZE) if mode != 'ECB' else None  # Odczytaj wektor IV jeśli istnieje
        encrypted_data = f.read()                        # Odczytaj zaszyfrowane dane

    # Wybór algorytmu szyfrowania i trybu
    if algorithm == 'AES':
        cipher_algorithm = algorithms.AES(key)
    elif algorithm == '3DES':
        cipher_algorithm = algorithms.TripleDES(key)
    else:
        raise ValueError("Unsupported algorithm. Choose either 'AES' or '3DES'.")

    if mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'ECB':
        cipher_mode = modes.ECB()
    else:
        raise ValueError("Unsupported mode. Choose either 'CBC' or 'ECB'.")

    # Inicjalizacja szyfru
    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # Odszyfrowanie danych
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Usunięcie paddingu
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Zapisanie odszyfrowanego pliku
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)

def encrypt_bmp(input_file_path, output_file_path, key, asymmetric_public_key, asymmetric_algorithm='rsa', algorithm='AES', mode='CBC'):
    # Rozmiar nagłówka BMP
    BMP_HEADER_SIZE = 54

    # Wczytanie pliku BMP
    with open(input_file_path, 'rb') as f:
        bmp_header = f.read(BMP_HEADER_SIZE)  # Odczytaj nagłówek
        bmp_data = f.read()                   # Odczytaj dane obrazowe

    # Dodanie paddingu do danych obrazowych
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(bmp_data) + padder.finalize()

    # Inicjalizacja wektora IV
    iv = os.urandom(8 if algorithm == '3DES' else 16) if mode != 'ECB' else None

    # Wybór algorytmu szyfrowania i trybu
    if algorithm == 'AES':
        cipher_algorithm = algorithms.AES(key)
    elif algorithm == '3DES':
        cipher_algorithm = algorithms.TripleDES(key)
    else:
        raise ValueError("Unsupported algorithm. Choose either 'AES' or '3DES'.")

    if mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'ECB':
        cipher_mode = modes.ECB()
    else:
        raise ValueError("Unsupported mode. Choose either 'CBC' or 'ECB'.")

    # Inicjalizacja szyfru
    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    # Szyfrowanie danych obrazowych
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    #dodanie metadanych do pliku wyjsciowego
    key = encrypt_symmetric_key(key,asymmetric_public_key, asymmetric_algorithm)
    add_metadata_to_encrypted_file(output_file_path, iv, key, symmetric_algorithm=algorithm,mode=mode)

    # Zapisanie zaszyfrowanego pliku BMP z zachowaniem nagłówka
    with open(output_file_path, 'ab') as f:
        f.write(bmp_header)  # Zapisanie nagłówka
        if iv:               # Zapisanie wektora IV jeśli istnieje
            f.write(iv)
        f.write(encrypted_data)  # Zapisanie zaszyfrowanych danych obrazowych

def decrypt_bmp(input_file_path, output_file_path, key, algorithm='AES', mode='CBC'):
    # Rozmiar nagłówka BMP
    BMP_HEADER_SIZE = 54
    IV_SIZE = 8 if algorithm == '3DES' else 16

    # Wczytanie zaszyfrowanego pliku BMP
    with open(input_file_path, 'rb') as f:
        bmp_header = f.read(BMP_HEADER_SIZE)  # Odczytaj nagłówek
        iv = f.read(IV_SIZE) if mode != 'ECB' else None  # Odczytaj wektor IV jeśli istnieje
        encrypted_data = f.read()                       # Odczytaj zaszyfrowane dane obrazowe

    # Wybór algorytmu szyfrowania i trybu
    if algorithm == 'AES':
        cipher_algorithm = algorithms.AES(key)
    elif algorithm == '3DES':
        cipher_algorithm = algorithms.TripleDES(key)
    else:
        raise ValueError("Unsupported algorithm. Choose either 'AES' or '3DES'.")

    if mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'ECB':
        cipher_mode = modes.ECB()
    else:
        raise ValueError("Unsupported mode. Choose either 'CBC' or 'ECB'.")

    # Inicjalizacja szyfru
    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # Odszyfrowanie danych obrazowych
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Usunięcie paddingu
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Zapisanie odszyfrowanego pliku BMP z zachowaniem nagłówka
    with open(output_file_path, 'wb') as f:
        f.write(bmp_header)  # Zapisanie nagłówka
        f.write(decrypted_data)  # Zapisanie odszyfrowanych danych obrazowych


'''key_aes = os.urandom(32)  # 256-bitowy klucz AES
key_3des = os.urandom(24) # 192-bitowy klucz 3DES
encrypt_bmp('tux.bmp', 'encrypted_aes_cbc.bmp', key_aes, algorithm='AES', mode='CBC')
encrypt_bmp('tux.bmp', 'encrypted_aes_ecb.bmp', key_aes, algorithm='AES', mode='ECB')
encrypt_bmp('test.bmp', 'encrypted_3des_ecb.bmp', key_3des, algorithm='3DES', mode='ECB')'''

#decrypt_bmp('encrypted_aes_cbc.bmp', 'decrypted.bmp', key_aes, algorithm='AES', mode='CBC')

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_bmp_xor(input_file_path, output_file_path, key):
    # Rozmiar nagłówka BMP
    BMP_HEADER_SIZE = 54

    # Wczytanie pliku BMP
    with open(input_file_path, 'rb') as f:
        bmp_header = f.read(BMP_HEADER_SIZE)  # Odczytaj nagłówek
        bmp_data = f.read()                   # Odczytaj dane obrazowe

    # Szyfrowanie danych obrazowych za pomocą XOR
    encrypted_data = xor_encrypt(bmp_data, key)

    # Zapisanie zaszyfrowanego pliku BMP z zachowaniem nagłówka
    with open(output_file_path, 'wb') as f:
        f.write(bmp_header)     # Zapisanie nagłówka
        f.write(encrypted_data) # Zapisanie zaszyfrowanych danych obrazowych


'''key = b'secretkey'  # Klucz do szyfrowania XOR
encrypt_bmp_xor('test.bmp', 'encrypted_xor.bmp', key)'''

def exclude_metadata(input_file_path):
    # Otwarcie pliku w trybie do odczytu binarnego
    with open(input_file_path, 'rb+') as f:
        # Odczytanie metadanych z pliku
        metadata_line = f.readline().decode('utf-8')
        # Ustawienie wskaźnika na początku danych
        f.seek(len(metadata_line))
        # Odczytanie reszty danych po metadanych
        data = f.read()
        # Przycięcie pliku, usuwając metadane
        f.seek(0)
        f.write(data)
        f.truncate()
        # Parsowanie metadanych z linii jako JSON
        metadata = json.loads(metadata_line)
        # Zwrócenie metadanych
        return metadata

'''metadata = exclude_metadata('encrypted_aes_cbc.bmp')
print(metadata)'''
