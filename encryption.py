import base64
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

load_dotenv()
json_app_key = os.environ.get("json_app_key")
key = base64.b64decode(json_app_key)
print("Binary Key:",key)

def encrypt_otp(otp, key):
    otp_bytes = otp.encode()


    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding the OTP to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_data = padder.update(otp_bytes) + padder.finalize()

    encrypted_otp = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_otp

def decrypt_otp(encrypted_otp, key):
    iv = encrypted_otp[:16]
    encrypted_data = encrypted_otp[16:]


    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()


otp = "567127"

encrypted_otp = encrypt_otp(otp, key)
encrypted_otp_base64 = base64.b64encode(encrypted_otp).decode()

decrypted_otp = decrypt_otp(base64.b64decode(encrypted_otp_base64), key)

print("Original OTP:", otp)
print("Encrypted OTP (base64):", encrypted_otp_base64)
print("Decrypted OTP:", decrypted_otp)
