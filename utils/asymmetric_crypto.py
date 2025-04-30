from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import json
from .key_management import KeyManager
from .integrity import IntegrityVerifier

class AsymmetricCrypto:
    """
    非对称加密类，提供RSA加密/解密和签名/验证功能
    支持混合加密（RSA+AES）用于大文件加密
    """
    
    def __init__(self, private_key=None, public_key=None, key_size=2048):
        """
        初始化非对称加密器
        
        参数:
            private_key (RSA.RsaKey, optional): RSA私钥对象
            public_key (RSA.RsaKey, optional): RSA公钥对象
            key_size (int): 密钥大小(位)，默认为2048位
        """
        if private_key:
            self.private_key = private_key
            self.public_key = private_key.publickey() if not public_key else public_key
        elif public_key:
            self.public_key = public_key
            self.private_key = None
        else:
            # 生成新的密钥对
            key = RSA.generate(key_size)
            self.private_key = key
            self.public_key = key.publickey()
    
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
    
    def sign_data(self, data):
        """
        使用RSA私钥对数据进行签名
        
        参数:
            data (bytes): 要签名的数据
            
        返回:
            bytes: 签名
        """
        if not self.private_key:
            raise ValueError("签名需要私钥")
            
        h = SHA256.new(data)
        signature = pkcs1_15.new(self.private_key).sign(h)
        return signature
    
    def verify_signature(self, data, signature):
        """
        验证数据签名
        
        参数:
            data (bytes): 签名的数据
            signature (bytes): 签名
            
        返回:
            bool: 如果签名有效则返回True，否则返回False
        """
        h = SHA256.new(data)
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def hybrid_encrypt_data(self, data, add_signature=False):
        """
        使用混合加密（RSA+AES）加密数据
        适用于大数据量
        
        参数:
            data (bytes): 要加密的数据
            add_signature (bool): 是否添加签名
            
        返回:
            dict: 包含加密数据和元数据的字典
        """
        # 生成随机AES密钥和IV
        aes_key = get_random_bytes(32)  # 256位AES密钥
        iv = get_random_bytes(16)
        
        # 使用AES加密数据
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # 使用RSA加密AES密钥
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # 准备返回结果
        result = {
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'mode': 'hybrid'
        }
        
        # 如果需要添加签名
        if add_signature and self.private_key:
            signature = self.sign_data(data)
            result['signature'] = base64.b64encode(signature).decode('utf-8')
            
        return result
    
    def hybrid_decrypt_data(self, encrypted_package, verify_signature=False):
        """
        解密使用混合加密的数据
        
        参数:
            encrypted_package (dict): 包含加密数据和元数据的字典
            verify_signature (bool): 是否验证签名
            
        返回:
            bytes: 解密后的数据
        """
        if not self.private_key:
            raise ValueError("解密需要私钥")
            
        # 获取加密的AES密钥、IV和加密数据
        encrypted_aes_key = base64.b64decode(encrypted_package['encrypted_aes_key'])
        iv = base64.b64decode(encrypted_package['iv'])
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
        
        # 使用RSA解密AES密钥
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # 使用AES解密数据
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
        
        # 如果需要验证签名
        if verify_signature and 'signature' in encrypted_package:
            signature = base64.b64decode(encrypted_package['signature'])
            is_valid = self.verify_signature(decrypted_data, signature)
            if not is_valid:
                raise ValueError("签名验证失败")
                
        return decrypted_data
    
    def encrypt_file(self, input_file, output_file=None, add_signature=False, chunk_size=8192):
        """
        加密文件（使用混合加密）
        
        参数:
            input_file (str): 输入文件路径
            output_file (str, optional): 输出文件路径，如果不提供则在输入文件名后添加.enc后缀
            add_signature (bool): 是否添加签名
            chunk_size (int): 处理文件的块大小
            
        返回:
            str: 加密后的文件路径
        """
        if not output_file:
            output_file = input_file + '.enc'
            
        # 生成随机AES密钥和IV
        aes_key = get_random_bytes(32)  # 256位AES密钥
        iv = get_random_bytes(16)
        
        # 使用RSA加密AES密钥
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # 准备元数据
        metadata = {
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'mode': 'hybrid',
            'original_filename': os.path.basename(input_file)
        }
        
        # 如果需要添加签名，计算文件哈希并签名
        if add_signature and self.private_key:
            file_hash = IntegrityVerifier.calculate_file_hash(input_file)
            hash_bytes = base64.b64decode(file_hash)
            signature = self.sign_data(hash_bytes)
            metadata['signature'] = base64.b64encode(signature).decode('utf-8')
            metadata['hash_value'] = file_hash
        
        # 创建AES加密器
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # 写入加密文件
        with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            # 写入元数据
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')
            out_file.write(metadata_length)
            out_file.write(metadata_bytes)
            
            # 逐块读取并加密文件内容
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk, AES.block_size)
                out_file.write(cipher_aes.encrypt(chunk))
                
        return output_file
    
    def decrypt_file(self, input_file, output_file=None, verify_signature=False, chunk_size=8192):
        """
        解密文件
        
        参数:
            input_file (str): 输入文件路径
            output_file (str, optional): 输出文件路径，如果不提供则根据元数据或去除.enc后缀
            verify_signature (bool): 是否验证签名
            chunk_size (int): 处理文件的块大小
            
        返回:
            str: 解密后的文件路径
        """
        if not self.private_key:
            raise ValueError("解密需要私钥")
            
        # 读取文件前4个字节，确定元数据长度
        with open(input_file, 'rb') as in_file:
            metadata_length_bytes = in_file.read(4)
            metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
            metadata_bytes = in_file.read(metadata_length)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
        
        # 确定输出文件路径
        if not output_file:
            if 'original_filename' in metadata:
                output_dir = os.path.dirname(input_file)
                output_file = os.path.join(output_dir, metadata['original_filename'])
            else:
                if input_file.endswith('.enc'):
                    output_file = input_file[:-4]
                else:
                    output_file = input_file + '.dec'
        
        # 获取加密的AES密钥和IV
        encrypted_aes_key = base64.b64decode(metadata['encrypted_aes_key'])
        iv = base64.b64decode(metadata['iv'])
        
        # 使用RSA解密AES密钥
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # 创建AES解密器
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # 解密文件
        with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            # 跳过元数据
            in_file.seek(4 + metadata_length)
            
            # 读取并解密最后一块之前的所有块
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                
                # 检查是否是最后一块
                if len(chunk) < chunk_size:
                    # 最后一块需要去除填充
                    decrypted_chunk = unpad(cipher_aes.decrypt(chunk), AES.block_size)
                else:
                    decrypted_chunk = cipher_aes.decrypt(chunk)
                
                out_file.write(decrypted_chunk)
        
        # 验证签名
        if verify_signature and 'signature' in metadata and 'hash_value' in metadata:
            # 计算解密后文件的哈希值
            actual_hash = IntegrityVerifier.calculate_file_hash(output_file)
            
            # 验证哈希值是否匹配
            if actual_hash != metadata['hash_value']:
                os.remove(output_file)
                raise ValueError("文件哈希值不匹配")
                
            # 验证签名
            signature = base64.b64decode(metadata['signature'])
            hash_bytes = base64.b64decode(metadata['hash_value'])
            if not self.verify_signature(hash_bytes, signature):
                os.remove(output_file)
                raise ValueError("文件签名验证失败")
        
        return output_file
    
    def save_keys(self, private_filename, public_filename, password=None):
        """
        保存密钥对到文件
        
        参数:
            private_filename (str): 私钥文件名
            public_filename (str): 公钥文件名
            password (str, optional): 用于加密私钥的密码
            
        返回:
            tuple: (私钥文件路径, 公钥文件路径)
        """
        if not self.private_key:
            raise ValueError("没有私钥可保存")
            
        key_manager = KeyManager()
        return key_manager.save_asymmetric_keys(
            self.private_key.export_key(),
            self.public_key.export_key(),
            private_filename,
            public_filename,
            password
        )
    
    @classmethod
    def load_from_key_files(cls, private_filename=None, public_filename=None, password=None):
        """
        从密钥文件加载非对称加密器
        
        参数:
            private_filename (str, optional): 私钥文件名
            public_filename (str, optional): 公钥文件名
            password (str, optional): 解密私钥的密码
            
        返回:
            AsymmetricCrypto: 非对称加密器实例
        """
        key_manager = KeyManager()
        private_key = None
        public_key = None
        
        if private_filename:
            private_key = key_manager.load_private_key(private_filename, password)
            
        if public_filename:
            public_key = key_manager.load_public_key(public_filename)
            
        if not private_key and not public_key:
            raise ValueError("必须提供至少一个密钥文件")
            
        return cls(private_key=private_key, public_key=public_key)