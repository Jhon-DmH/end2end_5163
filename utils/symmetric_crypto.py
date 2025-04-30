from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import base64
import json
from .key_management import KeyManager
from .integrity import IntegrityVerifier

class SymmetricCrypto:
    """
    对称加密类，提供AES加密/解密功能
    支持文件和数据的加密/解密操作
    """
    
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
        
        # 如果需要添加完整性校验
        if add_integrity:
            hmac = IntegrityVerifier.generate_hmac(data, self.key)
            result['hmac'] = hmac
            
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
        
        # 如果需要验证完整性
        if verify_integrity and 'hmac' in encrypted_package:
            is_valid = IntegrityVerifier.verify_hmac(
                decrypted_data, 
                encrypted_package['hmac'], 
                self.key
            )
            if not is_valid:
                raise ValueError("数据完整性验证失败")
                
        return decrypted_data
    
    def encrypt_file(self, input_file, output_file=None, chunk_size=8192, add_metadata=True):
        """
        加密文件
        
        参数:
            input_file (str): 输入文件路径
            output_file (str, optional): 输出文件路径，如果不提供则在输入文件名后添加.enc后缀
            chunk_size (int): 处理文件的块大小
            add_metadata (bool): 是否添加元数据
            
        返回:
            str: 加密后的文件路径
        """
        if not output_file:
            output_file = input_file + '.enc'
            
        # 生成随机IV
        iv = get_random_bytes(16)
        
        # 创建AES加密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # 准备元数据
        metadata = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'mode': 'CBC',
            'original_filename': os.path.basename(input_file)
        }
        
        # 如果需要添加完整性校验，计算文件哈希
        if add_metadata:
            integrity_metadata = IntegrityVerifier.create_integrity_metadata(input_file, self.key)
            metadata.update(integrity_metadata)
        
        # 写入加密文件
        with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            # 如果添加元数据，先写入元数据
            if add_metadata:
                metadata_bytes = json.dumps(metadata).encode('utf-8')
                metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')
                out_file.write(metadata_length)
                out_file.write(metadata_bytes)
            else:
                # 如果不添加元数据，只写入IV
                out_file.write(iv)
            
            # 逐块读取并加密文件内容
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk, AES.block_size)
                out_file.write(cipher.encrypt(chunk))
                
        return output_file
    
    def decrypt_file(self, input_file, output_file=None, chunk_size=8192, verify_integrity=True):
        """
        解密文件
        
        参数:
            input_file (str): 输入文件路径
            output_file (str, optional): 输出文件路径，如果不提供则根据元数据或去除.enc后缀
            chunk_size (int): 处理文件的块大小
            verify_integrity (bool): 是否验证文件完整性
            
        返回:
            str: 解密后的文件路径
        """
        # 读取文件前4个字节，确定元数据长度
        with open(input_file, 'rb') as in_file:
            try:
                metadata_length_bytes = in_file.read(4)
                metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                metadata_bytes = in_file.read(metadata_length)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
                has_metadata = True
            except:
                # 如果读取元数据失败，假设文件没有元数据，只有IV
                in_file.seek(0)
                iv = in_file.read(16)
                has_metadata = False
        
        # 确定输出文件路径
        if not output_file:
            if has_metadata and 'original_filename' in metadata:
                output_dir = os.path.dirname(input_file)
                output_file = os.path.join(output_dir, metadata['original_filename'])
            else:
                if input_file.endswith('.enc'):
                    output_file = input_file[:-4]
                else:
                    output_file = input_file + '.dec'
        
        # 获取IV
        if has_metadata:
            iv = base64.b64decode(metadata['iv'])
        
        # 创建AES解密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # 解密文件
        with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            # 跳过元数据
            if has_metadata:
                in_file.seek(4 + metadata_length)
            else:
                in_file.seek(16)  # 跳过IV
            
            # 读取并解密最后一块之前的所有块
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                
                # 检查是否是最后一块
                if len(chunk) < chunk_size:
                    # 最后一块需要去除填充
                    decrypted_chunk = unpad(cipher.decrypt(chunk), AES.block_size)
                else:
                    decrypted_chunk = cipher.decrypt(chunk)
                
                out_file.write(decrypted_chunk)
        
        # 验证文件完整性
        if verify_integrity and has_metadata:
            if not IntegrityVerifier.verify_file_integrity(output_file, metadata, self.key):
                # 如果验证失败，删除解密的文件并抛出异常
                os.remove(output_file)
                raise ValueError("文件完整性验证失败")
        
        return output_file
    
    def save_key(self, filename, password=None):
        """
        保存密钥到文件
        
        参数:
            filename (str): 文件名
            password (str, optional): 用于加密密钥的密码
            
        返回:
            str: 密钥文件路径
        """
        key_manager = KeyManager()
        return key_manager.save_symmetric_key(self.key, filename, password)
    
    @classmethod
    def load_from_key_file(cls, filename, password=None):
        """
        从密钥文件加载对称加密器
        
        参数:
            filename (str): 密钥文件名
            password (str, optional): 解密密钥的密码
            
        返回:
            SymmetricCrypto: 对称加密器实例
        """
        key_manager = KeyManager()
        key = key_manager.load_symmetric_key(filename, password)
        return cls(key=key)