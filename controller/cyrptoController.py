from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import json

from controller.utils.key_management import KeyManager


class CryptoController:
    def __init__(self):
        """
        初始化非对称加密器

        参数:
            private_key (RSA.RsaKey, optional): RSA私钥对象
            public_key (RSA.RsaKey, optional): RSA公钥对象
            key_size (int): 密钥大小(位)，默认为2048位
        """
        self.keyManager = KeyManager()

    def encrypt_data(self, data):
        """
        使用RSA公钥加密数据
        注意：仅适用于小数据量，不超过密钥大小减去padding大小

        参数:
            data (bytes): 要加密的数据

        返回:
            bytes: 加密后的数据
        """
        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(data)

    def decrypt_data(self, encrypted_data):
        """
        使用RSA私钥解密数据

        参数:
            encrypted_data (bytes): 加密的数据

        返回:
            bytes: 解密后的数据
        """
        if not self.private_key:
            raise ValueError("解密需要私钥")

        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(encrypted_data)

    def generate_asyKey(self):
        private_key, public_Key = self.keyManager.generate_asymmetric_keys()
        self.keyManager.save_asymmetric_keys(private_key, public_Key, 'server_private_key.pem', 'server_public_Key.pem')
        return public_Key

    def generate_smkey(self):
        Key = self.keyManager.generate_symmetric_key()
        self.keyManager.save_symmetric_key(Key, 'asy_key.key')
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
        return

    def save_publicKey(self,key):
        dir_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        try:
            key_path=os.path.join(dir_path, 'user_public_Key.pem')
            with open(key_path, 'wb') as f:
                f.write(key)
            return True
        except Exception as e:
            raise ValueError(f"Failed to get public key: {str(e)}")


class SymmetricController:
    def __init__(self, key=None, key_size=32):
        """
        初始化对称加密器

        参数:
            key (bytes, optional): AES密钥，如果不提供则自动生成
            key_size (int): 密钥大小(字节)，默认为32(256位)
        """
        self.key = key if key else get_random_bytes(key_size)
        self.key_size = key_size

    def encrypt_data(self, data, add_integrity=False):
        """
        加密数据

        参数:
            data (bytes): 要加密的数据
            add_integrity (bool): 是否添加完整性校验

        返回:
            dict: 包含加密数据和元数据的字典
        """
        # 生成随机IV
        iv = get_random_bytes(16)

        # 创建AES加密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # 填充并加密数据
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        # 准备返回结果
        result = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'mode': 'CBC'
        }
        return result

    def decrypt_data(self, encrypted_package, verify_integrity=False):
        """
        解密数据

        参数:
            encrypted_package (dict): 包含加密数据和元数据的字典
            verify_integrity (bool): 是否验证完整性

        返回:
            bytes: 解密后的数据
        """
        # 获取加密数据和IV
        iv = base64.b64decode(encrypted_package['iv'])
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])

        # 创建AES解密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # 解密并去除填充
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        return decrypted_data
