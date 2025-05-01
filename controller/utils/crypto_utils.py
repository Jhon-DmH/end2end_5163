from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import json
import logging
import base64
from enum import Enum
from .symmetric_crypto import SymmetricCrypto
from .asymmetric_crypto import AsymmetricCrypto
from .key_management import KeyManager
# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('crypto_utils')

class CryptoType(Enum):
    """加密类型枚举"""
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    AUTO = "auto"  # 自动选择（小数据用非对称，大数据用混合加密）

class CryptoConfig:
    """加密配置类"""
    
    def __init__(self, 
                 crypto_type=CryptoType.AUTO,
                 symmetric_key=None, 
                 symmetric_key_file=None,
                 symmetric_key_password=None,
                 private_key_file=None, 
                 public_key_file=None,
                 private_key_password=None,
                 add_signature=False,
                 verify_signature=False,
                 add_integrity=False,
                 verify_integrity=True,
                 chunk_size=8192,
                 key_size=2048):
        """
        初始化加密配置
        
        参数:
            crypto_type (CryptoType): 加密类型，默认为AUTO
            symmetric_key (bytes): 对称密钥
            symmetric_key_file (str): 对称密钥文件
            symmetric_key_password (str): 对称密钥密码
            private_key_file (str): 私钥文件
            public_key_file (str): 公钥文件
            private_key_password (str): 私钥密码
            add_signature (bool): 是否添加签名
            verify_signature (bool): 是否验证签名
            add_integrity (bool): 是否添加完整性校验
            verify_integrity (bool): 是否验证完整性
            chunk_size (int): 处理文件的块大小
            key_size (int): 密钥大小(位)，默认为2048位
        """
        self.crypto_type = crypto_type
        self.symmetric_key = symmetric_key
        self.symmetric_key_file = symmetric_key_file
        self.symmetric_key_password = symmetric_key_password
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self.private_key_password = private_key_password
        self.add_signature = add_signature
        self.verify_signature = verify_signature
        self.add_integrity = add_integrity
        self.verify_integrity = verify_integrity
        self.chunk_size = chunk_size
        self.key_size = key_size

class CryptoUtils:
    """
    统一加密工具类
    提供对称和非对称加密的统一接口
    自动处理大文件和异常情况
    """
    
    def __init__(self, config=None):
        """
        初始化加密工具
        
        参数:
            config (CryptoConfig): 加密配置，如果不提供则使用默认配置
        """
        self.config = config if config else CryptoConfig()
        self.symmetric_crypto = None
        self.asymmetric_crypto = None
        self.key_manager = KeyManager()
        
        # 初始化加密器
        self._initialize_crypto()
    
    def _initialize_crypto(self):
        """初始化加密器"""
        try:
            # 初始化对称加密
            if self.config.crypto_type in [CryptoType.SYMMETRIC, CryptoType.AUTO]:
                if self.config.symmetric_key:
                    self.symmetric_crypto = SymmetricCrypto(key=self.config.symmetric_key)
                elif self.config.symmetric_key_file:
                    key = self.key_manager.load_symmetric_key(
                        self.config.symmetric_key_file, 
                        self.config.symmetric_key_password
                    )
                    self.symmetric_crypto = SymmetricCrypto(key=key)
                else:
                    # 如果没有提供密钥，生成新的密钥
                    self.symmetric_crypto = SymmetricCrypto()
            
            # 初始化非对称加密
            if self.config.crypto_type in [CryptoType.ASYMMETRIC, CryptoType.AUTO]:
                if self.config.private_key_file or self.config.public_key_file:
                    self.asymmetric_crypto = AsymmetricCrypto.load_from_key_files(
                        private_filename=self.config.private_key_file,
                        public_filename=self.config.public_key_file,
                        password=self.config.private_key_password
                    )
                else:
                    # 如果没有提供密钥，生成新的密钥对
                    self.asymmetric_crypto = AsymmetricCrypto(key_size=self.config.key_size)
        except Exception as e:
            logger.error(f"初始化加密器失败: {str(e)}")
            raise
    
    def encrypt_data(self, data):
        """
        加密数据
        根据配置自动选择加密方式
        
        参数:
            data (bytes): 要加密的数据
            
        返回:
            dict: 包含加密数据和元数据的字典
        """
        if not isinstance(data, bytes):
            data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
        
        try:
            # 根据数据大小和配置选择加密方式
            if self.config.crypto_type == CryptoType.SYMMETRIC:
                if not self.symmetric_crypto:
                    raise ValueError("未初始化对称加密器")
                result = self.symmetric_crypto.encrypt_data(data, add_integrity=self.config.add_integrity)
                result['crypto_type'] = 'symmetric'
                return result
            
            elif self.config.crypto_type == CryptoType.ASYMMETRIC:
                if not self.asymmetric_crypto:
                    raise ValueError("未初始化非对称加密器")
                
                # 对于大数据，使用混合加密
                if len(data) > 200:  # RSA加密限制
                    result = self.asymmetric_crypto.hybrid_encrypt_data(
                        data, 
                        add_signature=self.config.add_signature
                    )
                else:
                    # 小数据直接使用RSA
                    encrypted_data = self.asymmetric_crypto.encrypt_data(data)
                    result = {
                        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                        'mode': 'rsa'
                    }
                    
                    # 如果需要添加签名
                    if self.config.add_signature and self.asymmetric_crypto.private_key:
                        signature = self.asymmetric_crypto.sign_data(data)
                        result['signature'] = base64.b64encode(signature).decode('utf-8')
                
                result['crypto_type'] = 'asymmetric'
                return result
            
            else:  # AUTO
                # 对于小数据且有非对称加密器时使用RSA
                if len(data) <= 200 and self.asymmetric_crypto and self.asymmetric_crypto.public_key:
                    encrypted_data = self.asymmetric_crypto.encrypt_data(data)
                    result = {
                        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                        'mode': 'rsa',
                        'crypto_type': 'asymmetric'
                    }
                    
                    # 如果需要添加签名
                    if self.config.add_signature and self.asymmetric_crypto.private_key:
                        signature = self.asymmetric_crypto.sign_data(data)
                        result['signature'] = base64.b64encode(signature).decode('utf-8')
                    
                    return result
                
                # 对于大数据且有非对称加密器时使用混合加密
                elif self.asymmetric_crypto and self.asymmetric_crypto.public_key:
                    result = self.asymmetric_crypto.hybrid_encrypt_data(
                        data, 
                        add_signature=self.config.add_signature
                    )
                    result['crypto_type'] = 'asymmetric'
                    return result
                
                # 如果没有非对称加密器或只有私钥，使用对称加密
                elif self.symmetric_crypto:
                    result = self.symmetric_crypto.encrypt_data(data, add_integrity=self.config.add_integrity)
                    result['crypto_type'] = 'symmetric'
                    return result
                
                else:
                    raise ValueError("未初始化任何加密器")
                
        except Exception as e:
            logger.error(f"加密数据失败: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_package):
        """
        解密数据
        根据加密包中的信息自动选择解密方式
        
        参数:
            encrypted_package (dict): 包含加密数据和元数据的字典
            
        返回:
            bytes: 解密后的数据
        """
        try:
            # 根据加密包中的信息选择解密方式
            crypto_type = encrypted_package.get('crypto_type')
            mode = encrypted_package.get('mode', '')
            
            if crypto_type == 'symmetric' or mode == 'CBC':
                if not self.symmetric_crypto:
                    raise ValueError("未初始化对称加密器")
                return self.symmetric_crypto.decrypt_data(
                    encrypted_package, 
                    verify_integrity=self.config.verify_integrity
                )
            
            elif crypto_type == 'asymmetric' or mode in ['rsa', 'hybrid']:
                if not self.asymmetric_crypto:
                    raise ValueError("未初始化非对称加密器")
                
                if mode == 'rsa':
                    # 直接RSA解密
                    encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
                    decrypted_data = self.asymmetric_crypto.decrypt_data(encrypted_data)
                    
                    # 如果需要验证签名
                    if self.config.verify_signature and 'signature' in encrypted_package:
                        signature = base64.b64decode(encrypted_package['signature'])
                        is_valid = self.asymmetric_crypto.verify_signature(decrypted_data, signature)
                        if not is_valid:
                            raise ValueError("签名验证失败")
                    
                    return decrypted_data
                
                else:  # hybrid
                    return self.asymmetric_crypto.hybrid_decrypt_data(
                        encrypted_package, 
                        verify_signature=self.config.verify_signature
                    )
            
            else:
                # 尝试自动检测加密类型
                if 'iv' in encrypted_package and 'encrypted_data' in encrypted_package:
                    if 'encrypted_aes_key' in encrypted_package:
                        # 混合加密
                        if not self.asymmetric_crypto:
                            raise ValueError("未初始化非对称加密器")
                        return self.asymmetric_crypto.hybrid_decrypt_data(
                            encrypted_package, 
                            verify_signature=self.config.verify_signature
                        )
                    else:
                        # 对称加密
                        if not self.symmetric_crypto:
                            raise ValueError("未初始化对称加密器")
                        return self.symmetric_crypto.decrypt_data(
                            encrypted_package, 
                            verify_integrity=self.config.verify_integrity
                        )
                else:
                    raise ValueError("无法识别的加密包格式")
                
        except Exception as e:
            logger.error(f"解密数据失败: {str(e)}")
            raise
    
    def encrypt_file(self, input_file, output_file=None):
        """
        加密文件
        根据配置自动选择加密方式
        
        参数:
            input_file (str): 输入文件路径
            output_file (str, optional): 输出文件路径
            
        返回:
            str: 加密后的文件路径
        """
        try:
            # 检查输入文件是否存在
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"输入文件不存在: {input_file}")
            
            # 根据配置选择加密方式
            if self.config.crypto_type == CryptoType.SYMMETRIC:
                if not self.symmetric_crypto:
                    raise ValueError("未初始化对称加密器")
                return self.symmetric_crypto.encrypt_file(
                    input_file, 
                    output_file, 
                    chunk_size=self.config.chunk_size, 
                    add_metadata=self.config.add_integrity
                )
            
            elif self.config.crypto_type == CryptoType.ASYMMETRIC:
                if not self.asymmetric_crypto:
                    raise ValueError("未初始化非对称加密器")
                return self.asymmetric_crypto.encrypt_file(
                    input_file, 
                    output_file, 
                    add_signature=self.config.add_signature, 
                    chunk_size=self.config.chunk_size
                )
            
            else:  # AUTO
                # 优先使用非对称加密（混合加密）
                if self.asymmetric_crypto and self.asymmetric_crypto.public_key:
                    return self.asymmetric_crypto.encrypt_file(
                        input_file, 
                        output_file, 
                        add_signature=self.config.add_signature, 
                        chunk_size=self.config.chunk_size
                    )
                # 如果没有非对称加密器，使用对称加密
                elif self.symmetric_crypto:
                    return self.symmetric_crypto.encrypt_file(
                        input_file, 
                        output_file, 
                        chunk_size=self.config.chunk_size, 
                        add_metadata=self.config.add_integrity
                    )
                else:
                    raise ValueError("未初始化任何加密器")
                
        except Exception as e:
            logger.error(f"加密文件失败: {str(e)}")
            raise
    
    def decrypt_file(self, input_file, output_file=None):
        """
        解密文件
        自动检测加密类型并解密
        
        参数:
            input_file (str): 输入文件路径
            output_file (str, optional): 输出文件路径
            
        返回:
            str: 解密后的文件路径
        """
        try:
            # 检查输入文件是否存在
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"输入文件不存在: {input_file}")
            
            # 尝试读取文件前4个字节，确定元数据长度
            with open(input_file, 'rb') as in_file:
                try:
                    metadata_length_bytes = in_file.read(4)
                    metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                    metadata_bytes = in_file.read(metadata_length)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    
                    # 根据元数据判断加密类型
                    if 'encrypted_aes_key' in metadata:
                        # 混合加密
                        if not self.asymmetric_crypto:
                            raise ValueError("未初始化非对称加密器")
                        return self.asymmetric_crypto.decrypt_file(
                            input_file, 
                            output_file, 
                            verify_signature=self.config.verify_signature, 
                            chunk_size=self.config.chunk_size
                        )
                    elif 'mode' in metadata and metadata['mode'] == 'CBC':
                        # 对称加密
                        if not self.symmetric_crypto:
                            raise ValueError("未初始化对称加密器")
                        return self.symmetric_crypto.decrypt_file(
                            input_file, 
                            output_file, 
                            chunk_size=self.config.chunk_size, 
                            verify_integrity=self.config.verify_integrity
                        )
                    else:
                        # 尝试使用对称解密
                        if self.symmetric_crypto:
                            try:
                                return self.symmetric_crypto.decrypt_file(
                                    input_file, 
                                    output_file, 
                                    chunk_size=self.config.chunk_size, 
                                    verify_integrity=self.config.verify_integrity
                                )
                            except Exception:
                                # 如果对称解密失败，尝试非对称解密
                                pass
                        
                        # 尝试使用非对称解密
                        if self.asymmetric_crypto:
                            return self.asymmetric_crypto.decrypt_file(
                                input_file, 
                                output_file, 
                                verify_signature=self.config.verify_signature, 
                                chunk_size=self.config.chunk_size
                            )
                        
                        raise ValueError("无法识别的加密文件格式")
                
                except Exception as e:
                    # 如果读取元数据失败，尝试使用对称解密（可能是没有元数据的旧格式）
                    if self.symmetric_crypto:
                        try:
                            return self.symmetric_crypto.decrypt_file(
                                input_file, 
                                output_file, 
                                chunk_size=self.config.chunk_size, 
                                verify_integrity=False
                            )
                        except Exception:
                            logger.error(f"对称解密失败: {str(e)}")
                    
                    # 如果对称解密失败，抛出异常
                    raise ValueError(f"解密文件失败: {str(e)}")
                
        except Exception as e:
            logger.error(f"解密文件失败: {str(e)}")
            raise
    
    def generate_keys(self, symmetric_key_file=None, private_key_file=None, public_key_file=None, password=None):
        """
        生成新的密钥
        
        参数:
            symmetric_key_file (str, optional): 对称密钥文件名
            private_key_file (str, optional): 私钥文件名
            public_key_file (str, optional): 公钥文件名
            password (str, optional): 密钥密码
            
        返回:
            dict: 包含生成的密钥信息的字典
        """
        result = {}
        
        try:
            # 生成对称密钥
            if symmetric_key_file:
                symmetric_key = self.key_manager.generate_symmetric_key()
                key_path = self.key_manager.save_symmetric_key(symmetric_key, symmetric_key_file, password)
                result['symmetric_key'] = {
                    'key': symmetric_key,
                    'file_path': key_path
                }
                # 更新当前对称加密器
                self.symmetric_crypto = SymmetricCrypto(key=symmetric_key)
            
            # 生成非对称密钥对
            if private_key_file and public_key_file:
                private_key, public_key = self.key_manager.generate_asymmetric_keys(key_size=self.config.key_size)
                private_path, public_path = self.key_manager.save_asymmetric_keys(
                    private_key, 
                    public_key, 
                    private_key_file, 
                    public_key_file, 
                    password
                )
                result['asymmetric_keys'] = {
                    'private_key': private_key,
                    'public_key': public_key,
                    'private_path': private_path,
                    'public_path': public_path
                }
                # 更新当前非对称加密器
                self.asymmetric_crypto = AsymmetricCrypto(
                    private_key=RSA.import_key(private_key),
                    public_key=RSA.import_key(public_key)
                )
            
            return result
            
        except Exception as e:
            logger.error(f"生成密钥失败: {str(e)}")
            raise

    @staticmethod
    def create_config_from_dict(config_dict):
        """
        从字典创建配置对象
        
        参数:
            config_dict (dict): 配置字典
            
        返回:
            CryptoConfig: 配置对象
        """
        # 处理加密类型
        if 'crypto_type' in config_dict:
            if isinstance(config_dict['crypto_type'], str):
                config_dict['crypto_type'] = CryptoType(config_dict['crypto_type'])
        
        # 创建配置对象
        return CryptoConfig(**config_dict)
    
    @staticmethod
    def load_config_from_file(config_file):
        """
        从文件加载配置
        
        参数:
            config_file (str): 配置文件路径
            
        返回:
            CryptoConfig: 配置对象
        """
        try:
            with open(config_file, 'r') as f:
                config_dict = json.load(f)
            
            return CryptoUtils.create_config_from_dict(config_dict)
            
        except Exception as e:
            logger.error(f"加载配置文件失败: {str(e)}")
            raise