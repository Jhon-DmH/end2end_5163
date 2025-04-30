import hashlib
import os
import json
from pathlib import Path

class HashVerifier:
    """
    文件哈希值验证工具类
    用于计算文件哈希值并验证文件完整性
    """
    
    @staticmethod
    def calculate_file_hash(file_path, algorithm='sha256'):
        """
        计算文件的哈希值
        
        参数:
            file_path (str): 文件路径
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            str: 文件的哈希值（十六进制字符串）
        
        异常:
            FileNotFoundError: 文件不存在时抛出
            ValueError: 不支持的哈希算法
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
            
        if algorithm.lower() not in ['md5', 'sha1', 'sha256', 'sha512']:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
            
        hash_obj = None
        if algorithm.lower() == 'md5':
            hash_obj = hashlib.md5()
        elif algorithm.lower() == 'sha1':
            hash_obj = hashlib.sha1()
        elif algorithm.lower() == 'sha256':
            hash_obj = hashlib.sha256()
        elif algorithm.lower() == 'sha512':
            hash_obj = hashlib.sha512()
            
        # 分块读取文件以处理大文件
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
                
        return hash_obj.hexdigest()
    
    @staticmethod
    def verify_file_hash(file_path, expected_hash, algorithm='sha256'):
        """
        验证文件哈希值是否匹配
        
        参数:
            file_path (str): 文件路径
            expected_hash (str): 期望的哈希值
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            bool: 如果哈希值匹配则返回True，否则返回False
        """
        try:
            actual_hash = HashVerifier.calculate_file_hash(file_path, algorithm)
            return actual_hash.lower() == expected_hash.lower()
        except (FileNotFoundError, ValueError) as e:
            print(f"验证哈希值时出错: {e}")
            return False
    
    @staticmethod
    def generate_hash_file(directory, output_file=None, algorithm='sha256'):
        """
        为目录中的所有文件生成哈希值并保存到JSON文件
        
        参数:
            directory (str): 目录路径
            output_file (str): 输出文件路径，默认为directory/file_hashes.json
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            dict: 文件路径到哈希值的映射
        """
        if not os.path.isdir(directory):
            raise NotADirectoryError(f"指定的路径不是目录: {directory}")
            
        if output_file is None:
            output_file = os.path.join(directory, "file_hashes.json")
            
        file_hashes = {}
        
        # 遍历目录中的所有文件
        for root, _, files in os.walk(directory):
            for file in files:
                # 跳过哈希文件本身
                if os.path.abspath(os.path.join(root, file)) == os.path.abspath(output_file):
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    file_hash = HashVerifier.calculate_file_hash(file_path, algorithm)
                    # 使用相对路径作为键
                    rel_path = os.path.relpath(file_path, directory)
                    file_hashes[rel_path] = file_hash
                except Exception as e:
                    print(f"处理文件 {file_path} 时出错: {e}")
        
        # 保存到JSON文件
        with open(output_file, 'w') as f:
            json.dump({
                'algorithm': algorithm,
                'hashes': file_hashes
            }, f, indent=4)
            
        return file_hashes
    
    @staticmethod
    def verify_directory(directory, hash_file=None, algorithm='sha256'):
        """
        验证目录中所有文件的完整性
        
        参数:
            directory (str): 目录路径
            hash_file (str): 哈希文件路径，默认为directory/file_hashes.json
            algorithm (str): 哈希算法，默认为sha256
            
        返回:
            tuple: (是否全部验证通过, 验证结果字典)
        """
        if not os.path.isdir(directory):
            raise NotADirectoryError(f"指定的路径不是目录: {directory}")
            
        if hash_file is None:
            hash_file = os.path.join(directory, "file_hashes.json")
            
        if not os.path.exists(hash_file):
            raise FileNotFoundError(f"哈希文件不存在: {hash_file}")
            
        # 加载哈希文件
        with open(hash_file, 'r') as f:
            hash_data = json.load(f)
            
        stored_algorithm = hash_data.get('algorithm', algorithm)
        stored_hashes = hash_data.get('hashes', {})
        
        verification_results = {}
        all_passed = True
        
        # 验证每个文件
        for rel_path, expected_hash in stored_hashes.items():
            file_path = os.path.join(directory, rel_path)
            if os.path.exists(file_path):
                is_valid = HashVerifier.verify_file_hash(file_path, expected_hash, stored_algorithm)
                verification_results[rel_path] = {
                    'exists': True,
                    'valid': is_valid
                }
                if not is_valid:
                    all_passed = False
            else:
                verification_results[rel_path] = {
                    'exists': False,
                    'valid': False
                }
                all_passed = False
                
        # 检查是否有新增文件
        for root, _, files in os.walk(directory):
            for file in files:
                # 跳过哈希文件本身
                if os.path.abspath(os.path.join(root, file)) == os.path.abspath(hash_file):
                    continue
                    
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, directory)
                
                if rel_path not in stored_hashes:
                    verification_results[rel_path] = {
                        'exists': True,
                        'valid': None,  # 新文件，没有预期的哈希值
                        'new_file': True
                    }
        
        return all_passed, verification_results


# 简单使用示例
if __name__ == "__main__":
    # 计算单个文件的哈希值
    try:
        file_path = "example.txt"
        with open(file_path, "w") as f:
            f.write("测试文件内容")
        
        file_hash = HashVerifier.calculate_file_hash(file_path)
        print(f"文件 {file_path} 的SHA256哈希值: {file_hash}")
        
        # 验证哈希值
        is_valid = HashVerifier.verify_file_hash(file_path, file_hash)
        print(f"哈希值验证结果: {'通过' if is_valid else '失败'}")
        
        # 为目录生成哈希文件
        directory = "."
        HashVerifier.generate_hash_file(directory)
        print(f"已为目录 {directory} 生成哈希文件")
        
        # 验证目录
        all_passed, results = HashVerifier.verify_directory(directory)
        print(f"目录验证结果: {'全部通过' if all_passed else '存在问题'}")
        print(f"详细结果: {results}")
        
    except Exception as e:
        print(f"发生错误: {e}")
