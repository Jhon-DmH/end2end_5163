import socket
import json
import os
from controller.userController import UserController
from utils.crypto_utils import CryptoUtils
from controller.hashController import HashController
from utils.crypto_utils import CryptoUtils, CryptoConfig, CryptoType
import base64
import shutil



class Server:
    def __init__(self, host='localhost', port=5163):
        self.host = host
        self.port = port
        self.user_controller = UserController()
        
        # 初始化服务器密钥
        crypto_1 = CryptoUtils()
        keys = crypto_1.generate_keys(
            symmetric_key_file="server_symmetric_key.key",
            private_key_file="server_private_key.pem",
            public_key_file="server_public_key.pem",
            password="test_password"
        )  
                    
        print("\n服务器密钥已生成:")
        if 'symmetric_key' in keys:
            print(f"- 对称密钥文件: {keys['symmetric_key']['file_path']}")
    
        if 'asymmetric_keys' in keys:
            print(f"- 私钥文件: {keys['asymmetric_keys']['private_path']}")
            print(f"- 公钥文件: {keys['asymmetric_keys']['public_path']}")
        
    def get_user_files(self, username):
        """获取用户文件列表"""
        user_dir = f"data/{username}"
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        files = []
        for file in os.listdir(user_dir):
            file_path = os.path.join(user_dir, file)
            if os.path.isfile(file_path):
                files.append(f"📄 {file}")
            else:
                files.append(f"📁 {file}")
        return files

    def get_all_files(self):
        """获取所有文件列表"""
        files = []
        for root, dirs, filenames in os.walk("data"):
            rel_path = os.path.relpath(root, "data")
            if rel_path != ".":
                files.append(f"📁 {rel_path}")
            for file in filenames:
                file_path = os.path.join(rel_path, file)
                if rel_path == ".":
                    files.append(f"📄 {file}")
                else:
                    files.append(f"📄 {file_path}")
        return files

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"服务器启动在 {self.host}:{self.port}")
        
        while True:
            client_socket, address = server_socket.accept()
            print(f"接收到来自 {address} 的连接")
            
            try:
                # 接收请求
                # 接收请求
                data = b""
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # 尝试检测是否已接收完整的JSON数据
                    try:
                        json.loads(data.decode('utf-8'))
                        break  # 如果能成功解析JSON，说明数据接收完毕
                    except:
                        continue  # 否则继续接收
                        
                request_data = json.loads(data.decode('utf-8'))
                
                # 根据请求类型处理
                request_type = request_data.get('type', '')
                
                if request_type == 'auth':
                    # 处理认证请求
                    username = request_data.get('username')
                    password = request_data.get('password')
                    user = self.user_controller.authenticate(username, password)
                    response = {
                        'success': bool(user),
                        'user': user if user else None
                    }
                elif request_type == 'register':
                    # 处理注册请求
                    username = request_data.get('username')
                    password = request_data.get('password')
                    success, message = self.user_controller.register_user(username, password)
                    response = {
                        'success': success,
                        'message': message
                    }
                elif request_type == 'get_files':
                    # 处理获取文件列表请求
                    username = request_data.get('username')
                    role = request_data.get('role')
                    if role == 'admin':
                        files = self.get_all_files()
                    else:
                        files = self.get_user_files(username)
                    response = {
                        'success': True,
                        'files': files
                    }
                elif request_type == 'delete_file':
                    # 处理删除文件请求
                    file_path = request_data.get('file_path')
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            response = {
                                'success': True
                            }
                        else:
                            response = {
                                'success': False,
                                'error': '文件不存在'
                            }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }
                
                elif request_type == 'check_integrity':
                    # 处理文件完整性检查请求
                    try:
                        data_dir = 'data/'
                        hash_file = 'data/file_hashes.json'
                        
                        # 确保data目录存在
                        if not os.path.exists(data_dir):
                            os.makedirs(data_dir)
                            
                        # 如果哈希文件不存在，创建一个新的
                        if not os.path.exists(hash_file):
                            HashController.generate_hash_file(data_dir, hash_file)
                            response = {
                                'success': True,
                                'verification_results': {}
                            }
                        else:
                            # 执行完整性检查
                            all_passed, verification_results = HashController.verify_directory(data_dir, hash_file)
                            response = {
                                'success': True,
                                'verification_results': verification_results
                            }
                            
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }

                elif request_type == 'update_hash_file':
                    # 处理更新哈希值文件请求
                    try:
                        HashController.generate_hash_file("data/")
                        response = {
                            'success': True
                        }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }
                
                elif request_type == 'transfer_public_key':
                    # 处理公钥传输请求
                    try:
                        username = request_data.get('username')
                        public_key = request_data.get('public_key')
                        
                        # 确保keys目录存在
                        keys_dir = 'keys'
                        if not os.path.exists(keys_dir):
                            os.makedirs(keys_dir)
                            
                        # 保存公钥
                        key_path = os.path.join(keys_dir, f"{username}_public_key.pem")
                        with open(key_path, 'w') as f:
                            f.write(public_key)
                            
                        response = {
                            'success': True,
                            'message': '公钥传输成功'
                        }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }

                elif request_type == 'get_server_public_key':
                    # 处理获取服务器公钥请求
                    try:
                        # 读取服务器公钥
                        public_key_path = os.path.join('keys', "server_public_key.pem")
                        if not os.path.exists(public_key_path):
                            response = {
                                'success': False,
                                'error': '服务器公钥不存在'
                            }
                        else:
                            with open(public_key_path, 'r') as f:
                                public_key = f.read()
                                
                            response = {
                                'success': True,
                                'public_key': public_key
                            }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }

                elif request_type == 'download_file':
                    # 处理文件下载请求
                    try:
                        file_path = request_data.get('file_path')
                        username = request_data.get('username')
                        
                        # 确保temp_server目录存在
                        temp_dir = 'temp_server'
                        if not os.path.exists(temp_dir):
                            os.makedirs(temp_dir)
                        
                        # 使用用户的公钥加密文件
                        config = CryptoConfig(
                            crypto_type=CryptoType.ASYMMETRIC,
                            public_key_file=f"{username}_public_key.pem",
                            add_signature=True
                        )
                        crypto = CryptoUtils(config)
                        print(file_path+'下载')
                        # 加密文件并保存到temp_server目录
                        encrypted_file = crypto.encrypt_file(file_path, 'temp_server/file_asym.enc')
                        
                        # 读取加密后的文件
                        with open(encrypted_file, 'rb') as f:
                            encrypted_data = f.read()
                        
                        response = {
                            'success': True,
                            'encrypted_file': base64.b64encode(encrypted_data).decode('utf-8')
                        }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }

                elif request_type == 'upload_file':
                    # 处理文件上传请求
                    try:
                        username = request_data.get('username')
                        file_name = request_data.get('file_name')
                        encrypted_file_data = base64.b64decode(request_data.get('encrypted_file'))
                        
                        # 确保temp_server目录存在
                        temp_dir = 'temp_server'
                        if not os.path.exists(temp_dir):
                            os.makedirs(temp_dir)
                        
                        # 保存加密文件到临时目录
                        encrypted_file_path = os.path.join(temp_dir, 'file_asym.enc')
                        with open(encrypted_file_path, 'wb') as f:
                            f.write(encrypted_file_data)
                        
                        # 使用服务器私钥解密文件
                        config = CryptoConfig(
                            crypto_type=CryptoType.ASYMMETRIC,
                            private_key_file="server_private_key.pem",
                            private_key_password="test_password",
                            verify_signature=True
                        )
                        crypto = CryptoUtils(config)
                        
                        # 解密文件
                        decrypted_file = crypto.decrypt_file(encrypted_file_path)
                        
                        # 确保用户目录存在
                        user_dir = f"data/{username}"
                        if not os.path.exists(user_dir):
                            os.makedirs(user_dir)
                        
                        # 移动解密后的文件到用户目录
                        target_path = os.path.join(user_dir, file_name)
                        shutil.move(decrypted_file, target_path)
                        
                        # 更新哈希文件
                        HashController.generate_hash_file("data/")
                        
                        response = {
                            'success': True,
                            'message': '文件上传成功'
                        }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }

                elif request_type == 'init_upload':
                    # 处理初始化上传请求
                    try:
                        username = request_data.get('username')
                        file_name = request_data.get('file_name')
                        total_chunks = request_data.get('total_chunks')
                        
                        # 确保临时目录存在
                        temp_dir = os.path.join('temp_server', username)
                        if not os.path.exists(temp_dir):
                            os.makedirs(temp_dir)
                        
                        # 创建临时文件记录
                        temp_info = {
                            'file_name': file_name,
                            'total_chunks': total_chunks,
                            'received_chunks': 0,
                            'temp_path': os.path.join(temp_dir, f"{file_name}.temp")
                        }
                        
                        # 保存临时文件信息
                        with open(os.path.join(temp_dir, f"{file_name}.info"), 'w') as f:
                            json.dump(temp_info, f)
                        
                        response = {
                            'success': True,
                            'message': '文件上传初始化成功'
                        }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }
                
                elif request_type == 'upload_chunk':
                    # 处理文件块上传
                    try:
                        username = request_data.get('username')
                        file_name = request_data.get('file_name')
                        chunk_index = request_data.get('chunk_index')
                        chunk_data = base64.b64decode(request_data.get('chunk_data'))
                        
                        # 临时目录
                        temp_dir = os.path.join('temp_server', username)
                        info_path = os.path.join(temp_dir, f"{file_name}.info")
                        
                        # 读取临时文件信息
                        with open(info_path, 'r') as f:
                            temp_info = json.load(f)
                        
                        # 追加数据到临时文件
                        with open(temp_info['temp_path'], 'ab') as f:
                            f.write(chunk_data)
                        
                        # 更新接收块数
                        temp_info['received_chunks'] += 1
                        with open(info_path, 'w') as f:
                            json.dump(temp_info, f)
                        
                        response = {
                            'success': True,
                            'message': f'块 {chunk_index+1}/{temp_info["total_chunks"]} 上传成功'
                        }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }
                
                elif request_type == 'complete_upload':
                    # 处理完成上传请求
                    try:
                        username = request_data.get('username')
                        file_name = request_data.get('file_name')
                        
                        # 临时目录
                        temp_dir = os.path.join('temp_server', username)
                        info_path = os.path.join(temp_dir, f"{file_name}.info")
                        
                        # 读取临时文件信息
                        with open(info_path, 'r') as f:
                            temp_info = json.load(f)
                        
                        # 检查是否所有块都已接收
                        if temp_info['received_chunks'] != temp_info['total_chunks']:
                            response = {
                                'success': False,
                                'error': f'文件不完整，已接收 {temp_info["received_chunks"]}/{temp_info["total_chunks"]} 块'
                            }
                        else:
                            # 使用服务器私钥解密文件
                            config = CryptoConfig(
                                crypto_type=CryptoType.ASYMMETRIC,
                                private_key_file="server_private_key.pem",
                                private_key_password="test_password",
                                verify_signature=True
                            )
                            crypto = CryptoUtils(config)
                            
                            # 解密文件
                            decrypted_file = crypto.decrypt_file(temp_info['temp_path'])
                            
                            # 确保用户目录存在
                            user_dir = f"data/{username}"
                            if not os.path.exists(user_dir):
                                os.makedirs(user_dir)
                            
                            # 移动解密后的文件到用户目录
                            target_path = os.path.join(user_dir, file_name)
                            shutil.move(decrypted_file, target_path)
                            
                            # 更新哈希文件
                            HashController.generate_hash_file("data/")
                            
                            # 清理临时文件
                            os.remove(temp_info['temp_path'])
                            os.remove(info_path)
                            
                            response = {
                                'success': True,
                                'message': '文件上传成功'
                            }
                    except Exception as e:
                        response = {
                            'success': False,
                            'error': str(e)
                        }

                else:
                    response = {
                        'success': False,
                        'error': 'Unknown request type'
                    }
                
                client_socket.send(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                error_response = {
                    'success': False,
                    'error': str(e)
                }
                client_socket.send(json.dumps(error_response).encode('utf-8'))
            
            finally:
                client_socket.close()

if __name__ == '__main__':
    server = Server()
    server.start()