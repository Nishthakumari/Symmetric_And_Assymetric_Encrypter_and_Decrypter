import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

backend = default_backend()



class assymmetric_crypto():


    BOBpublic_key_serealized=None
    ALICEpublic_key_serealized=None
    keyciphertext=None
    ivciphertext=None
    signature=None
    key=None
    iv=None

    __ALICEprivatekeyserealise=None
    __BOBprivate_key_serealized=None
    ct=None

    def gen_alice_asym_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
        public_key = private_key.public_key()
        pemprivate = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
        pempublic = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("\n A's pemprivate : ",pemprivate)
        print("\n Alice's pempublic :",pempublic)

    def gen_bob_asym_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        pemprivate = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
        pempublic = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        BOBpublic_key_serealized= pempublic
        print("\nBOB's pemprivate : ",pemprivate)
        print("\nBOB's pempublic : ",pempublic)
        return pemprivate;

    def send_sym_key_alice_to_bob():
        BOBpublic_key = serialization.load_pem_public_key(
        BOBpublic_key_serealized,
        backend=default_backend()
        )


        keyciphertext = BOBpublic_key.encrypt(
        key,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
        )

        ivciphertext= BOBpublic_key.encrypt(
        iv,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
        )
        ALICEprivate_key = serialization.load_pem_private_key(
        __ALICEprivatekeyserealise,
        password=None,
        backend=default_backend()
        )


        message = b"A message I want to sign"
        signature = ALICEprivate_key.sign(
        message,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )


        print("\nKeyCipherText : ",keyciphertext)
        print("\nivCipherText : ",ivciphertext)
        print("\nSignature : ",signature)


    def recieve_the_key_bob_to_alice():
        BOBprivate_key = serialization.load_pem_private_key(
        BOBprivate_key_serealized,
        password=None,
        backend=default_backend()
        )
        key = BOBprivate_key.decrypt(
        keyciphertext,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
        )
        iv = BOBprivate_key.decrypt(
        ivciphertext,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
        )
        ALICEpublic_key = serialization.load_pem_public_key(
        ALICEpublic_key_serealized,
        backend=default_backend()
        )


        print(key)
        print(iv)


        checkmessage=b"A message I want to sign"
        ALICEpublic_key.verify(
        signature,
        checkmessage,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )
    def send_msg_from_alice(message):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()

        #decryptor = cipher.decryptor()
        #decryptor.update(ct) + decryptor.finalize()
        print("\nmessage to be sent : ",message)
        print("\nCipher Text Generated ",ct)
        print("\nMessage sent successfully ")


    def recieve_message_to_bob():

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        #message=b"a secret messageabc             "
        #encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        decryptedmessage=decryptor.update(ct) + decryptor.finalize()
        print("\nMessage recieved")
        print("\nDecrypted message : ",decryptedmessage)



while(1):
    print("\n1->Generate Alice's pair of public and private keys")
    print("\n2->Generate bob's pair of public and private keys")
    print("\n3->Send a symmetric key from alice to bob")
    print("\n4->Recieve the key")
    print("\n5->Send a message form alice")
    print("\n6->Recieve a message by bob")
    print("\n7->Quit")

    n=int(input("\nEnter your choice: "))

    if n==1:
        gen_alice_asym_keys()
    elif n==2:
        gen_bob_asym_keys()
    elif n==3:
        send_sym_key_alice_to_bob()
    elif n==4:
        recieve_the_key_bob_to_alice()
    elif n==5:
        if len(message)%32!=0:
            r=32-len(message)%32
            message+=r*" ";
            binarymessage= message.encode()
        send_msg_from_alice(binarymessage)

    elif n==6:
         recieve_message_to_bob()
    elif n==7:
        break;
