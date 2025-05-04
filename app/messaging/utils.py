from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64
import os

def generate_aes_key():
    return get_random_bytes(32)  # 256-bit key

def encrypt_message_aes(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return iv, encrypted_message

def decrypt_message_aes(encrypted_message, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    try:
        decrypted_message = unpad(decrypted_padded_message, AES.block_size).decode('utf-8')
    except ValueError:
        return None  # Padding is incorrect
    return decrypted_message

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    recipient_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    private_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def generate_hash(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    sha256 = SHA256.new()
    sha256.update(data)
    return sha256.hexdigest()

def verify_hash(data, hash_value):
    return generate_hash(data) == hash_value

def encrypt_file(file_data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv, encrypted_data

def decrypt_file(encrypted_data, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_data = cipher.decrypt(encrypted_data)
    try:
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
    except ValueError:
        return None  # Padding is incorrect
    return decrypted_data