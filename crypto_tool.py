import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Constants
BLOCK_SIZE = AES.block_size        # 16 bytes
KEY_SIZE = 32                      # 32 bytes = 256 bits (AES-256)
SALT_SIZE = 16                     # 128-bit salt
ITERATIONS = 100000

def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def derive_key(password, salt):
    # Correct: using Crypto.Hash.SHA256, not hashlib
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

def encrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    with open(output_path, "wb") as f:
        f.write(salt + iv + ciphertext)  # Store salt + iv + ciphertext

    print(f"[+] File encrypted and saved to {output_path}")

def decrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        file_data = f.read()

    salt = file_data[:SALT_SIZE]
    iv = file_data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
    ciphertext = file_data[SALT_SIZE + BLOCK_SIZE:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] File decrypted and saved to {output_path}")
