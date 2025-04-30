from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

import base64
import os

BLOCK_SIZE = AES.block_size
class Cryptor:

    #----Entrance-------
    def __init__(self,encryptMode):
        self.mode=encryptMode;
        if self.mode!= "AES" and self.mode!= 'RAS':
            #mode selection error
            return False


    def encrypt_file(self,file,current_user):
        if(self.mode=='RAS'):
            return  False
        else:
            key=bytes("7d21c9ec805342d5bb4f96f1b92a12f0", "utf-8")
            encrypted_file=self.aes_encrypt(file,key)
            return encrypted_file


    def decrypt_file(self, file,current_user):
        if (self.mode == 'RAS'):
            return False
        else:
            key = bytes("7d21c9ec805342d5bb4f96f1b92a12f0", "utf-8")
            decrypted_file = self.aes_decrypt(file,key)
            return decrypted_file

    # ----------- AES-----------
    def pad(self,data) :
        padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
        return data + bytes([padding_len]) * padding_len

    def unpad(self,data) :
        padding_len = data[-1]
        if padding_len > BLOCK_SIZE:
            raise ValueError("Invalid padding")
        return data[:-padding_len]

    def aes_encrypt(self,data,key) :
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 128, 192, or 256 bits")
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(self.pad(data))
        return base64.b64encode(iv + ciphertext).decode()

    def aes_decrypt(self,encoded_data, key):
        raw = base64.b64decode(encoded_data)
        iv, ct = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(ct))

    # ----------- RSA_Key-----------
    def generate_rsa_keypair(bits=2048) :
        key = RSA.generate(bits)
        return key.export_key(), key.publickey().export_key()

    def save_rsa_keys(private_key: bytes, public_key: bytes, folder="keys"):
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "private.pem"), 'wb') as f:
            f.write(private_key)
        with open(os.path.join(folder, "public.pem"), 'wb') as f:
            f.write(public_key)

    def load_rsa_keys(folder="keys") :
        with open(os.path.join(folder, "private.pem"), 'rb') as f:
            private_key = f.read()
        with open(os.path.join(folder, "public.pem"), 'rb') as f:
            public_key = f.read()
        return private_key, public_key

    # ----------- AES密钥加解密（通过RSA） -----------

    def rsa_encrypt(data: bytes, public_key: bytes):
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(data)

    def rsa_decrypt(cipher_data: bytes, private_key: bytes):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(cipher_data)
