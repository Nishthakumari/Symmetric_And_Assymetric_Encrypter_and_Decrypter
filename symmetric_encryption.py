import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)




def decrypter(ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decryptedmessage=decryptor.update(ct) + decryptor.finalize()
    print("\n Decrypted message : ",decryptedmessage)


def encryptor(message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    print("\nEncryted message : " ,ct)
    return ct;
    
    
message=input("Enter the string to be encrypted ")

if len(message)%32!=0:
    r=32-len(message)%32
    message+=r*" ";
binarymessage= message.encode()

ciphertext=encryptor(binarymessage)
decrypter(ciphertext)
    
