from Crypto.Hash import SHA256, HMAC
import os
import json
import base64

class IntegrityVerifier:
    """
    提供文件完整性验证功能的类
    支持计算文件哈希值和HMAC签名验证
    """
    
    @staticmethod
    def calculate_file_hash(file_path, algorithm='sha256', chunk_size=8192):
        """
        计算文件的哈希值
        
        参数:
            file_path (str): 文件路径
            algorithm (str): 哈希算法，默认为sha256
            chunk_size (int): 读取文件的块大小
            
        返回:
            str: 文件的哈希值(base64编码)
        """
        if algorithm.lower() == 'sha256':
            hash_obj = SHA256.new()
            
            with open(file_path, 'rb') as file:
                for chunk in iter(lambda: file.read(chunk_size), b''):
                    hash_obj.update(chunk)
                    
            return base64.b64encode(hash_obj.digest()).decode('utf-8')
        else:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
    
    @staticmethod
    def verify_file_hash(file_path, expected_hash, algorithm='sha256'):
        """
        验证文件的哈希值是否匹配预期值
        
        参数:
            file_path (str): 文件路径
            expected_hash (str): 预期的哈希值(base64编码)
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            bool: 如果哈希值匹配则返回True，否则返回False
        """
        actual_hash = IntegrityVerifier.calculate_file_hash(file_path, algorithm)
        return actual_hash == expected_hash
    
    @staticmethod
    def generate_hmac(data, key, algorithm='sha256'):
        """
        使用密钥生成数据的HMAC
        
        参数:
            data (bytes): 要签名的数据
            key (bytes): HMAC密钥
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            str: HMAC签名(base64编码)
        """
        if algorithm.lower() == 'sha256':
            h = HMAC.new(key, digestmod=SHA256)
            h.update(data)
            return base64.b64encode(h.digest()).decode('utf-8')
        else:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
    
    @staticmethod
    def verify_hmac(data, signature, key, algorithm='sha256'):
        """
        验证数据的HMAC签名
        
        参数:
            data (bytes): 签名的数据
            signature (str): HMAC签名(base64编码)
            key (bytes): HMAC密钥
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            bool: 如果签名有效则返回True，否则返回False
        """
        expected_hmac = IntegrityVerifier.generate_hmac(data, key, algorithm)
        return expected_hmac == signature
    
    @staticmethod
    def create_integrity_metadata(file_path, key=None):
        """
        创建文件的完整性元数据，包括哈希值和可选的HMAC
        
        参数:
            file_path (str): 文件路径
            key (bytes, optional): 用于HMAC的密钥，如果不提供则不生成HMAC
            
        返回:
            dict: 包含完整性信息的字典
        """
        metadata = {
            'filename': os.path.basename(file_path),
            'size': os.path.getsize(file_path),
            'hash_algorithm': 'sha256',
            'hash_value': IntegrityVerifier.calculate_file_hash(file_path)
        }
        
        if key:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            metadata['hmac_algorithm'] = 'sha256'
            metadata['hmac_value'] = IntegrityVerifier.generate_hmac(file_data, key)
            
        return metadata
    
    @staticmethod
    def save_integrity_metadata(metadata, output_path):
        """
        将完整性元数据保存到文件
        
        参数:
            metadata (dict): 完整性元数据
            output_path (str): 输出文件路径
        """
        with open(output_path, 'w') as file:
            json.dump(metadata, file, indent=4)
    
    @staticmethod
    def load_integrity_metadata(metadata_path):
        """
        从文件加载完整性元数据
        
        参数:
            metadata_path (str): 元数据文件路径
            
        返回:
            dict: 完整性元数据
        """
        with open(metadata_path, 'r') as file:
            return json.load(file)
    
    @staticmethod
    def verify_file_integrity(file_path, metadata, key=None):
        """
        验证文件的完整性
        
        参数:
            file_path (str): 文件路径
            metadata (dict): 完整性元数据
            key (bytes, optional): 用于HMAC验证的密钥
            
        返回:
            bool: 如果文件完整性验证通过则返回True，否则返回False
        """
        # 验证文件大小
        if os.path.getsize(file_path) != metadata.get('size'):
            return False
        
        # 验证文件哈希
        if not IntegrityVerifier.verify_file_hash(
            file_path, 
            metadata.get('hash_value'),
            metadata.get('hash_algorithm', 'sha256')
        ):
            return False
        
        # 如果提供了密钥且元数据中包含HMAC，则验证HMAC
        if key and 'hmac_value' in metadata:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            if not IntegrityVerifier.verify_hmac(
                file_data,
                metadata.get('hmac_value'),
                key,
                metadata.get('hmac_algorithm', 'sha256')
            ):
                return False
                
        return True