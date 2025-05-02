import os
import sys
import random
import string
from utils.crypto_utils import CryptoUtils, CryptoConfig, CryptoType

# 确保测试目录存在
def ensure_dirs_exist():
    dirs = [
        'test/encrypt',
        'test/decrypt',
        'keys'
    ]
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
    print(f"测试目录已创建")

# 生成测试文件
def generate_test_files():
    # 生成小文件 (100字节)
    small_file_path = 'test/encrypt/small_file.txt'
    with open(small_file_path, 'w', encoding='utf-8') as f:
        f.write(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(100)))
    
    # 生成大文件 (1MB)
    large_file_path = 'test/encrypt/large_file.txt'
    with open(large_file_path, 'w', encoding='utf-8') as f:
        f.write(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(1024 * 1024)))
    
    print(f"测试文件已生成:")
    print(f"- 小文件: {os.path.abspath(small_file_path)} ({os.path.getsize(small_file_path)} 字节)")
    print(f"- 大文件: {os.path.abspath(large_file_path)} ({os.path.getsize(large_file_path)} 字节)")
    
    return small_file_path, large_file_path

# 生成并保存密钥
def generate_and_save_keys():
    # 创建加密工具实例
    crypto = CryptoUtils()
    
    # 生成对称密钥和非对称密钥对
    keys = crypto.generate_keys(
        symmetric_key_file="symmetric_key.key",
        private_key_file="private_key.pem",
        public_key_file="public_key.pem",
        password="test_password"
    )
    
    print("\n密钥已生成:")
    if 'symmetric_key' in keys:
        print(f"- 对称密钥文件: {keys['symmetric_key']['file_path']}")
    
    if 'asymmetric_keys' in keys:
        print(f"- 私钥文件: {keys['asymmetric_keys']['private_path']}")
        print(f"- 公钥文件: {keys['asymmetric_keys']['public_path']}")
    
    return keys

# 使用对称加密测试
def test_symmetric_encryption(small_file, large_file):
    print("\n=== 测试对称加密 ===")
    
    # 创建使用对称加密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.SYMMETRIC,
        symmetric_key_file="symmetric_key.key",
        symmetric_key_password="test_password"
    )
    crypto = CryptoUtils(config)
    
    # 加密小文件
    small_encrypted = crypto.encrypt_file(small_file, 'test/encrypt/small_file_sym.enc')
    print(f"小文件已加密: {small_encrypted}")
    
    # 加密大文件
    large_encrypted = crypto.encrypt_file(large_file, 'test/encrypt/large_file_sym.enc')
    print(f"大文件已加密: {large_encrypted}")
    
    return small_encrypted, large_encrypted

# 使用非对称加密测试
def test_asymmetric_encryption(small_file, large_file):
    print("\n=== 测试非对称加密 ===")
    
    # 创建使用非对称加密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.ASYMMETRIC,
        public_key_file="public_key.pem",
        private_key_password="test_password",
        add_signature=True
    )
    crypto = CryptoUtils(config)
    
    # 加密小文件
    small_encrypted = crypto.encrypt_file(small_file, 'test/encrypt/small_file_asym.enc')
    print(f"小文件已加密: {small_encrypted}")
    
    # 加密大文件
    large_encrypted = crypto.encrypt_file(large_file, 'test/encrypt/large_file_asym.enc')
    print(f"大文件已加密: {large_encrypted}")
    
    return small_encrypted, large_encrypted

# 使用自动选择加密测试
def test_auto_encryption(small_file, large_file):
    print("\n=== 测试自动选择加密 ===")
    
    # 创建使用自动选择加密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.AUTO,
        symmetric_key_file="symmetric_key.key",
        private_key_file="private_key.pem",
        public_key_file="public_key.pem",
        symmetric_key_password="test_password",
        private_key_password="test_password",
        add_signature=True,
        add_integrity=True
    )
    crypto = CryptoUtils(config)
    
    # 加密小文件
    small_encrypted = crypto.encrypt_file(small_file, 'test/encrypt/small_file_auto.enc')
    print(f"小文件已加密: {small_encrypted}")
    
    # 加密大文件
    large_encrypted = crypto.encrypt_file(large_file, 'test/encrypt/large_file_auto.enc')
    print(f"大文件已加密: {large_encrypted}")
    
    return small_encrypted, large_encrypted

def main():
    print("=== 开始加密测试 ===\n")
    
    # 确保测试目录存在
    ensure_dirs_exist()
    
    # 生成测试文件
    small_file, large_file = generate_test_files()
    
    # 生成并保存密钥
    keys = generate_and_save_keys()
    
    # 测试对称加密
    sym_small, sym_large = test_symmetric_encryption(small_file, large_file)
    
    # 测试非对称加密
    asym_small, asym_large = test_asymmetric_encryption(small_file, large_file)
    
    # 测试自动选择加密
    auto_small, auto_large = test_auto_encryption(small_file, large_file)
    
    # 保存加密文件路径到文件，供解密脚本使用
    with open('test/encrypt_results.txt', 'w') as f:
        f.write(f"sym_small:{sym_small}\n")
        f.write(f"sym_large:{sym_large}\n")
        f.write(f"asym_small:{asym_small}\n")
        f.write(f"asym_large:{asym_large}\n")
        f.write(f"auto_small:{auto_small}\n")
        f.write(f"auto_large:{auto_large}\n")
    
    print("\n加密测试完成！加密文件路径已保存到 test/encrypt_results.txt")

if __name__ == "__main__":
    main()