import os
import sys
from utils.crypto_utils import CryptoUtils, CryptoConfig, CryptoType

# 确保测试目录存在
def ensure_dirs_exist():
    os.makedirs('test/decrypt', exist_ok=True)
    print(f"解密输出目录已确认")

# 读取加密文件路径
def read_encrypted_files():
    with open('test/encrypt_results.txt', 'r') as f:
        lines = f.readlines()
    
    files = {}
    for line in lines:
        key, path = line.strip().split(':', 1)
        files[key] = path
    
    return files

# 使用对称解密测试
def test_symmetric_decryption(encrypted_files):
    print("\n=== 测试对称解密 ===")
    
    # 创建使用对称解密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.SYMMETRIC,
        symmetric_key_file="symmetric_key.key",
        symmetric_key_password="test_password",
        verify_integrity=True
    )
    crypto = CryptoUtils(config)
    
    # 打印密钥文件位置
    key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, "symmetric_key.key"))
    print(f"使用对称密钥文件: {key_path}")
    
    # 解密小文件
    small_decrypted = crypto.decrypt_file(
        encrypted_files['sym_small'], 
        'test/decrypt/small_file_sym_decrypted.txt'
    )
    print(f"小文件已解密: {small_decrypted}")
    
    # 解密大文件
    large_decrypted = crypto.decrypt_file(
        encrypted_files['sym_large'], 
        'test/decrypt/large_file_sym_decrypted.txt'
    )
    print(f"大文件已解密: {large_decrypted}")
    
    return small_decrypted, large_decrypted

# 使用非对称解密测试
def test_asymmetric_decryption(encrypted_files):
    print("\n=== 测试非对称解密 ===")
    
    # 创建使用非对称解密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.ASYMMETRIC,
        private_key_file="private_key.pem",
        public_key_file="public_key.pem",
        private_key_password="test_password",
        verify_signature=True
    )
    crypto = CryptoUtils(config)
    
    # 打印密钥文件位置
    private_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, "private_key.pem"))
    public_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, "public_key.pem"))
    print(f"使用私钥文件: {private_key_path}")
    print(f"使用公钥文件: {public_key_path}")
    
    # 解密小文件
    small_decrypted = crypto.decrypt_file(
        encrypted_files['asym_small'], 
        'test/decrypt/small_file_asym_decrypted.txt'
    )
    print(f"小文件已解密: {small_decrypted}")
    
    # 解密大文件
    large_decrypted = crypto.decrypt_file(
        encrypted_files['asym_large'], 
        'test/decrypt/large_file_asym_decrypted.txt'
    )
    print(f"大文件已解密: {large_decrypted}")
    
    return small_decrypted, large_decrypted

# 使用自动选择解密测试
def test_auto_decryption(encrypted_files):
    print("\n=== 测试自动选择解密 ===")
    
    # 创建使用自动选择解密的配置
    config = CryptoConfig(
        crypto_type=CryptoType.AUTO,
        symmetric_key_file="symmetric_key.key",
        private_key_file="private_key.pem",
        public_key_file="public_key.pem",
        symmetric_key_password="test_password",
        private_key_password="test_password",
        verify_signature=True,
        verify_integrity=True
    )
    crypto = CryptoUtils(config)
    
    # 打印密钥文件位置
    sym_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, "symmetric_key.key"))
    private_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, "private_key.pem"))
    public_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, "public_key.pem"))
    print(f"使用对称密钥文件: {sym_key_path}")
    print(f"使用私钥文件: {private_key_path}")
    print(f"使用公钥文件: {public_key_path}")
    
    # 解密小文件
    small_decrypted = crypto.decrypt_file(
        encrypted_files['auto_small'], 
        'test/decrypt/small_file_auto_decrypted.txt'
    )
    print(f"小文件已解密: {small_decrypted}")
    
    # 解密大文件
    large_decrypted = crypto.decrypt_file(
        encrypted_files['auto_large'], 
        'test/decrypt/large_file_auto_decrypted.txt'
    )
    print(f"大文件已解密: {large_decrypted}")
    
    return small_decrypted, large_decrypted

# 验证解密结果
def verify_decryption_results():
    print("\n=== 验证解密结果 ===")
    
    # 读取原始文件
    with open('test/encrypt/small_file.txt', 'r', encoding='utf-8') as f:
        original_small = f.read()
    
    with open('test/encrypt/large_file.txt', 'r', encoding='utf-8') as f:
        original_large = f.read()
    
    # 验证对称解密结果
    with open('test/decrypt/small_file_sym_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_small = f.read()
    print(f"对称小文件解密验证: {'成功' if original_small == decrypted_small else '失败'}")
    
    with open('test/decrypt/large_file_sym_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_large = f.read()
    print(f"对称大文件解密验证: {'成功' if original_large == decrypted_large else '失败'}")
    
    # 验证非对称解密结果
    with open('test/decrypt/small_file_asym_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_small = f.read()
    print(f"非对称小文件解密验证: {'成功' if original_small == decrypted_small else '失败'}")
    
    with open('test/decrypt/large_file_asym_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_large = f.read()
    print(f"非对称大文件解密验证: {'成功' if original_large == decrypted_large else '失败'}")
    
    # 验证自动选择解密结果
    with open('test/decrypt/small_file_auto_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_small = f.read()
    print(f"自动选择小文件解密验证: {'成功' if original_small == decrypted_small else '失败'}")
    
    with open('test/decrypt/large_file_auto_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_large = f.read()
    print(f"自动选择大文件解密验证: {'成功' if original_large == decrypted_large else '失败'}")

def main():
    print("=== 开始解密测试 ===\n")
    
    # 确保测试目录存在
    ensure_dirs_exist()
    
    # 读取加密文件路径
    encrypted_files = read_encrypted_files()
    print(f"读取到的加密文件:")
    for key, path in encrypted_files.items():
        print(f"- {key}: {path}")
    
    # 测试对称解密
    test_symmetric_decryption(encrypted_files)
    
    # 测试非对称解密
    test_asymmetric_decryption(encrypted_files)
    
    # 测试自动选择解密
    test_auto_decryption(encrypted_files)
    
    # 验证解密结果
    verify_decryption_results()
    
    print("\n解密测试完成！")

if __name__ == "__main__":
    main()