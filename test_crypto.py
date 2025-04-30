import os
import sys
import base64
from utils.crypto_utils import CryptoUtils, CryptoConfig, CryptoType

def test_symmetric_encryption():
    """测试对称加密"""
    print("=== 测试对称加密 ===")
    
    # 创建一个使用对称加密的配置
    config = CryptoConfig(crypto_type=CryptoType.SYMMETRIC)
    crypto = CryptoUtils(config)
    
    # 加密字符串
    original_data = "这是一个需要加密的敏感信息"
    print(f"原始数据: {original_data}")
    
    # 加密数据
    encrypted_package = crypto.encrypt_data(original_data)
    print(f"加密后的数据包: {encrypted_package}")
    
    # 解密数据
    decrypted_data = crypto.decrypt_data(encrypted_package)
    print(f"解密后的数据: {decrypted_data.decode('utf-8')}")
    
    # 验证解密结果
    assert original_data == decrypted_data.decode('utf-8')
    print("对称加密测试成功！\n")

def test_asymmetric_encryption():
    """测试非对称加密"""
    print("=== 测试非对称加密 ===")
    
    # 创建一个使用非对称加密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.ASYMMETRIC,
        add_signature=True,
        verify_signature=True
    )
    crypto = CryptoUtils(config)
    
    # 加密小数据（使用RSA直接加密）
    small_data = "短消息测试"
    print(f"原始小数据: {small_data}")
    
    encrypted_small = crypto.encrypt_data(small_data)
    print(f"加密后的小数据包: {encrypted_small}")
    
    decrypted_small = crypto.decrypt_data(encrypted_small)
    print(f"解密后的小数据: {decrypted_small.decode('utf-8')}")
    
    # 加密大数据（使用混合加密）
    large_data = "这是一个较长的消息，" * 20  # 重复文本使其超过RSA直接加密的限制
    print(f"原始大数据长度: {len(large_data)} 字节")
    
    encrypted_large = crypto.encrypt_data(large_data)
    print(f"加密后的大数据包模式: {encrypted_large.get('mode')}")
    
    decrypted_large = crypto.decrypt_data(encrypted_large)
    print(f"解密后的大数据长度: {len(decrypted_large)} 字节")
    
    # 验证解密结果
    assert small_data == decrypted_small.decode('utf-8')
    assert large_data == decrypted_large.decode('utf-8')
    print("非对称加密测试成功！\n")

def test_file_encryption():
    """测试文件加密"""
    print("=== 测试文件加密 ===")
    
    # 创建测试文件
    test_file = "test_file.txt"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("这是测试文件的内容，将被加密和解密。" * 10)
    
    # 使用自动选择加密方式
    config = CryptoConfig(
        crypto_type=CryptoType.AUTO,
        add_integrity=True,
        verify_integrity=True
    )
    crypto = CryptoUtils(config)
    
    # 加密文件
    encrypted_file = crypto.encrypt_file(test_file)
    print(f"文件已加密: {encrypted_file}")
    
    # 解密文件
    decrypted_file = crypto.decrypt_file(encrypted_file)
    print(f"文件已解密: {decrypted_file}")
    
    # 验证解密结果
    with open(test_file, "r", encoding="utf-8") as f1, open(decrypted_file, "r", encoding="utf-8") as f2:
        original_content = f1.read()
        decrypted_content = f2.read()
        assert original_content == decrypted_content
    
    # 清理测试文件
    try:
        os.remove(test_file)
        os.remove(encrypted_file)
        os.remove(decrypted_file)
    except:
        pass
    
    print("文件加密测试成功！\n")

def test_key_generation():
    """测试密钥生成"""
    print("=== 测试密钥生成 ===")
    
    crypto = CryptoUtils()
    
    # 生成对称密钥和非对称密钥对
    keys = crypto.generate_keys(
        symmetric_key_file="sym_key.key",
        private_key_file="private.pem",
        public_key_file="public.pem",
        password="test_password"
    )
    
    print("密钥已生成:")
    if 'symmetric_key' in keys:
        print(f"- 对称密钥文件: {keys['symmetric_key']['file_path']}")
    
    if 'asymmetric_keys' in keys:
        print(f"- 私钥文件: {keys['asymmetric_keys']['private_path']}")
        print(f"- 公钥文件: {keys['asymmetric_keys']['public_path']}")
    
    # 使用生成的密钥创建新的加密工具
    config = CryptoConfig(
        symmetric_key_file="sym_key.key",
        private_key_file="private.pem",
        public_key_file="public.pem",
        private_key_password="test_password",
        symmetric_key_password="test_password"
    )
    new_crypto = CryptoUtils(config)
    
    # 测试使用新密钥加密解密
    test_data = "使用新生成的密钥测试加密和解密"
    encrypted = new_crypto.encrypt_data(test_data)
    decrypted = new_crypto.decrypt_data(encrypted)
    
    assert test_data == decrypted.decode('utf-8')
    print("使用生成的密钥加密解密测试成功！")
    
    # 清理密钥文件
    try:
        os.remove("sym_key.key")
        os.remove("private.pem")
        os.remove("public.pem")
    except:
        pass
    
    print("密钥生成测试成功！\n")

def test_auto_crypto_selection():
    """测试自动选择加密方式"""
    print("=== 测试自动选择加密方式 ===")
    
    # 默认配置使用AUTO模式
    crypto = CryptoUtils()
    
    # 测试小数据
    small_data = "小数据测试"
    small_encrypted = crypto.encrypt_data(small_data)
    print(f"小数据加密模式: {small_encrypted.get('mode')}")
    
    # 测试大数据
    large_data = "大数据测试" * 100
    large_encrypted = crypto.encrypt_data(large_data)
    print(f"大数据加密模式: {large_encrypted.get('mode')}")
    
    # 解密并验证
    small_decrypted = crypto.decrypt_data(small_encrypted).decode('utf-8')
    large_decrypted = crypto.decrypt_data(large_encrypted).decode('utf-8')
    
    assert small_data == small_decrypted
    assert large_data == large_decrypted
    print("自动选择加密方式测试成功！\n")

if __name__ == "__main__":
    try:
        test_symmetric_encryption()
        test_asymmetric_encryption()
        test_file_encryption()
        test_key_generation()
        test_auto_crypto_selection()
        
        print("所有测试通过！")
    except Exception as e:
        print(f"测试失败: {str(e)}")