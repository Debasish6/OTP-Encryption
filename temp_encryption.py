import os,base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

def encrypt_otp(otp, key):
    """Encrypts a 6-digit OTP using AES-256 in CBC mode.

    Args:
        otp: The 6-digit OTP to encrypt.
        key: The 256-bit encryption key.

    Returns:
        The encrypted OTP in base64 format, truncated to 24 characters.
    """

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_data = padding.PKCS7(algorithms.AES.block_size).padder().update(otp.encode()) + padding.PKCS7(algorithms.AES.block_size).padder().finalize()
    encrypted_otp = encryptor.update(padded_data) + encryptor.finalize()

    combined = iv + encrypted_otp
    combined_base64 = base64.b64encode(combined).decode()

    return combined_base64[:24]

def decrypt_otp(encrypted_otp_base64, key):
    """Decrypts a 24-character base64-encoded OTP.

    Args:
        encrypted_otp_base64: The 24-character base64-encoded OTP.
        key: The 256-bit encryption key.

    Returns:
        The decrypted OTP.
    """

    encrypted_otp = base64.b64decode(encrypted_otp_base64)
    iv = encrypted_otp[:16]
    encrypted_data = encrypted_otp[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# Example usage:
load_dotenv()
json_app_key = os.environ.get("json_app_key")

key = base64.b64decode(json_app_key)
print("Binary Key:",key)
#key = b'your_256_bit_secret_key'  # Replace with your actual key
otp = "123456"

encrypted_otp = encrypt_otp(otp, key)
print("Encrypted OTP:", encrypted_otp)

# decrypted_otp = decrypt_otp(encrypted_otp, key)
# print("Decrypted OTP:", decrypted_otp)