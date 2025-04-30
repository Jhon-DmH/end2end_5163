from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import os
import base64
import json
from pathlib import Path

class KeyManager:
    """
    密钥管理类，用于生成、存储和加载加密密钥
    支持对称密钥(AES)和非对称密钥对(RSA)
    """
    
    def __init__(self, keys_dir=None):
        """
        初始化密钥管理器
        
        参数:
            keys_dir (str, optional): 存储密钥的目录，默认为当前目录下的'keys'文件夹
        """
        if keys_dir is None:
            self.keys_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
        else:
            self.keys_dir = keys_dir
            
        # 确保密钥目录存在
        os.makedirs(self.keys_dir, exist_ok=True)
    
    def generate_symmetric_key(self, key_size=32):
        """
        生成对称加密密钥(AES)
        
        参数:
            key_size (int): 密钥大小(字节)，默认为32(256位)
            
        返回:
            bytes: 生成的密钥
        """
        return get_random_bytes(key_size)
    
    def generate_asymmetric_keys(self, key_size=2048):
        """
        生成非对称加密密钥对(RSA)
        
        参数:
            key_size (int): 密钥大小(位)，默认为2048位
            
        返回:
            tuple: (私钥, 公钥)
        """
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    def save_symmetric_key(self, key, filename, password=None):
        """
        保存对称密钥到文件
        
        参数:
            key (bytes): 要保存的密钥
            filename (str): 保存的文件名
            password (str, optional): 用于加密密钥的密码
            
        返回:
            str: 密钥文件的完整路径
        """
        key_path = os.path.join(self.keys_dir, filename)
        
        # 如果提供了密码，使用密码加密密钥
        if password:
            # 这里简单实现，实际应用中应使用更安全的方式
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            
            salt = get_random_bytes(16)
            key_enc = PBKDF2(password.encode(), salt, dkLen=32)
            
            cipher = AES.new(key_enc, AES.MODE_CBC)
            iv = cipher.iv
            encrypted_key = cipher.encrypt(pad(key, AES.block_size))
            
            data = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
            }
            
            with open(key_path, 'w') as f:
                json.dump(data, f)
        else:
            # 不加密，直接保存base64编码的密钥
            with open(key_path, 'wb') as f:
                f.write(base64.b64encode(key))
                
        return key_path
    
    def load_symmetric_key(self, filename, password=None):
        """
        从文件加载对称密钥
        
        参数:
            filename (str): 密钥文件名
            password (str, optional): 解密密钥的密码
            
        返回:
            bytes: 加载的密钥
        """
        key_path = os.path.join(self.keys_dir, filename)
        
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"密钥文件不存在: {key_path}")
        
        if password:
            # 解密密钥
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            with open(key_path, 'r') as f:
                data = json.load(f)
                
            salt = base64.b64decode(data['salt'])
            iv = base64.b64decode(data['iv'])
            encrypted_key = base64.b64decode(data['encrypted_key'])
            
            key_enc = PBKDF2(password.encode(), salt, dkLen=32)
            cipher = AES.new(key_enc, AES.MODE_CBC, iv)
            
            try:
                key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
                return key
            except Exception as e:
                raise ValueError(f"密码错误或密钥文件已损坏: {str(e)}")
        else:
            # 直接加载base64编码的密钥
            with open(key_path, 'rb') as f:
                return base64.b64decode(f.read())
    
    def save_asymmetric_keys(self, private_key, public_key, private_filename, public_filename, password=None):
        """
        保存非对称密钥对到文件
        
        参数:
            private_key (bytes): 私钥
            public_key (bytes): 公钥
            private_filename (str): 私钥文件名
            public_filename (str): 公钥文件名
            password (str, optional): 用于加密私钥的密码
            
        返回:
            tuple: (私钥文件路径, 公钥文件路径)
        """
        private_key_path = os.path.join(self.keys_dir, private_filename)
        public_key_path = os.path.join(self.keys_dir, public_filename)
        
        # 保存公钥
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
        
        # 保存私钥，可选择加密
        if password:
            # 使用密码保护私钥
            encrypted_key = RSA.import_key(private_key).export_key(
                passphrase=password, 
                pkcs=8,
                protection="scryptAndAES128-CBC"
            )
            with open(private_key_path, 'wb') as f:
                f.write(encrypted_key)
        else:
            with open(private_key_path, 'wb') as f:
                f.write(private_key)
                
        return private_key_path, public_key_path
    
    def load_private_key(self, filename, password=None):
        """
        加载RSA私钥
        
        参数:
            filename (str): 私钥文件名
            password (str, optional): 解密私钥的密码
            
        返回:
            RSA.RsaKey: RSA私钥对象
        """
        key_path = os.path.join(self.keys_dir, filename)
        
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"私钥文件不存在: {key_path}")
        
        with open(key_path, 'rb') as f:
            key_data = f.read()
            
        try:
            if password:
                return RSA.import_key(key_data, passphrase=password)
            else:
                return RSA.import_key(key_data)
        except Exception as e:
            raise ValueError(f"加载私钥失败: {str(e)}")
    
    def load_public_key(self, filename):
        """
        加载RSA公钥
        
        参数:
            filename (str): 公钥文件名
            
        返回:
            RSA.RsaKey: RSA公钥对象
        """
        key_path = os.path.join(self.keys_dir, filename)
        
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"公钥文件不存在: {key_path}")
        
        with open(key_path, 'rb') as f:
            key_data = f.read()
            
        try:
            return RSA.import_key(key_data)
        except Exception as e:
            raise ValueError(f"加载公钥失败: {str(e)}")
    
    def encrypt_symmetric_key_with_rsa(self, symmetric_key, rsa_public_key):
        """
        使用RSA公钥加密对称密钥
        
        参数:
            symmetric_key (bytes): 对称密钥
            rsa_public_key (RSA.RsaKey): RSA公钥对象
            
        返回:
            bytes: 加密后的对称密钥
        """
        cipher = PKCS1_OAEP.new(rsa_public_key)
        return cipher.encrypt(symmetric_key)
    
    def decrypt_symmetric_key_with_rsa(self, encrypted_key, rsa_private_key):
        """
        使用RSA私钥解密对称密钥
        
        参数:
            encrypted_key (bytes): 加密的对称密钥
            rsa_private_key (RSA.RsaKey): RSA私钥对象
            
        返回:
            bytes: 解密后的对称密钥
        """
        cipher = PKCS1_OAEP.new(rsa_private_key)
        return cipher.decrypt(encrypted_key)
    
    def key_exists(self, filename):
        """
        检查密钥文件是否存在
        
        参数:
            filename (str): 密钥文件名
            
        返回:
            bool: 如果文件存在则返回True，否则返回False
        """
        key_path = os.path.join(self.keys_dir, filename)
        return os.path.exists(key_path)