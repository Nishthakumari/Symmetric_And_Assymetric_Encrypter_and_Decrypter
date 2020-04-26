import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

message=input("Enter the string to be encrypted ")//get message as_user_input
binarymessage= message.encode()
encrypter(message)



def decrypter(key,iv,ct)://function to decrypt the chipher text
 cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
 decryptor = cipher.decryptor()
 decryptedmessage=decryptor.update(ct) + decryptor.finalize()
 print(decryptedmessage)


def encryptor(message)://function to encrypt the cipher text
 key = os.urandom(32)
 iv = os.urandom(16)
 cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
 encryptor = cipher.encryptor()
 ct = encryptor.update(message) + encryptor.finalize()
 decrypter(key,iv,ct);
