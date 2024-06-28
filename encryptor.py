from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def encrypt_message(message, password):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)

    return urlsafe_b64encode(salt + h.finalize() + ciphertext)

def save_encrypted_data(encrypted_data, filename="encrypted_data.txt"):
    with open(filename, "wb") as file:
        file.write(encrypted_data)

if __name__ == "__main__":
    message_to_encrypt = input("Enter the message to encrypt: ")
    password = input("Enter a strong password: ")
    
    encrypted_data = encrypt_message(message_to_encrypt, password)
    save_encrypted_data(encrypted_data)
    print("Message encrypted and saved.")
