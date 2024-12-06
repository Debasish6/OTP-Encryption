import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from dotenv import load_dotenv

load_dotenv()
json_app_key = os.environ.get("json_app_key")

key = base64.b64decode(json_app_key)

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_CBC)  # Using CBC mode for PKCS5 padding
    iv = cipher.iv
    padded_msg = pad(msg.encode('ascii'), AES.block_size)  # PKCS5 padding is effectively PKCS7 for AES
    ciphertext = cipher.encrypt(padded_msg)
    return iv, ciphertext

def decrypt(iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, AES.block_size).decode('ascii')
        return plaintext
    except:
        return False

nonce, ciphertext = encrypt(input('Enter a message: '))
plaintext = decrypt(nonce, ciphertext)

print(f'Cipher text: {base64.b64encode(ciphertext).decode()}')
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plain text: {plaintext}')
