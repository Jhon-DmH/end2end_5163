import os
import shutil
from tkinter import messagebox
from pathlib import Path
from utils.encryption import Cryptor
from controller.hashController import HashController
import socket
import json
from utils.crypto_utils import CryptoUtils, CryptoConfig, CryptoType
import base64
import re


class FileController:

    def __init__(self, user):
        self.current_user = user
        self.my_Cryptor = Cryptor("AES")
        self.server_host = 'localhost'
        self.server_port = 5163

        self.as_key = ''
        self.sm_key = ''

    def sy_upload(self, uploadName, fileName):
        # TODO: DO THE DECRYPTION OF THE KEY!
        username=self.current_user['username']
        config = CryptoConfig(
            crypto_type=CryptoType.SYMMETRIC,
            symmetric_key_file=f"{username}_symmetric_key.key",
            symmetric_key_password="test_password",
            verify_integrity=True
        ) 
        crypto = CryptoUtils(config)
        key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, f"{username}_symmetric_key.key"))
        print(f"使用对称密钥文件: {key_path}")

        def get_original_filename(encrypted_file):
            with open(encrypted_file, 'rb') as f:
                try:
                    metadata_length_bytes = f.read(4)
                    metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                    metadata_bytes = f.read(metadata_length)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    if 'original_filename' in metadata:
                        return metadata['original_filename']
                except:
                    pass
            return None



        file_decrypted = crypto.decrypt_file(uploadName)
        print(f"解密后文件路径: {file_decrypted}，文件名：{get_original_filename(uploadName)}")



        # TODO: DO THE DECRYPTION OF THE FILE!
        # TODO: decrypt data with sy key
        # decryptFile= .....
        with open(file_decrypted, 'rb') as decryptFile:
            data = decryptFile.read()
            self.uploadFile(data, fileName)

    def sy_download(self, fileName):
        username = self.current_user['username'] 

        # 确定文件路径
        if self.current_user['role'] == 'admin' and '/' in fileName:
            # 管理员下载子文件夹中的文件
            folder, name = fileName.split('/', 1)
            file_path =fileName
        elif self.current_user['role'] == 'admin':
            # 管理员下载根目录中的文件
            file_path = 'data/' + fileName
        else:
            # 普通用户下载自己文件夹中的文件
            file_path = 'data/' + self.current_user['username'] + '/' + fileName
        try:
            # 确保源文件存在
            if not os.path.exists(file_path):
                messagebox.showerror("Error", f"Source file does not exist: {fileName}")
                return '', False
            if file_path=='data/file_hashes.json' or file_path=='data/users.csv':
                messagebox.showerror("Error", f"You cannot download system file! : {fileName}")
                return '', False

            with open(file_path, 'rb') as file:
                original_content = file.read()
            file_hash = HashController.calculate_file_hash(original_content)
            hash_file = "data/file_hashes.json"
            try:
                with open(hash_file, 'r') as f:
                    hash_data = json.load(f)
                    algorithm = hash_data.get('algorithm', 'sha256')
                    hashes = hash_data.get('hashes', {})
            except:
                algorithm = 'sha256'
                hashes = {}

            src_hash = hash_data['hashes'][file_path]

            if src_hash != file_hash:
                messagebox.showerror("Error", f"Integrity checks failed: {fileName}")
                return "",  False

            config = CryptoConfig(
                crypto_type=CryptoType.SYMMETRIC,
                symmetric_key_file=f"{username}_symmetric_key.key",
                symmetric_key_password="test_password"
            )
            crypto = CryptoUtils(config)
            # TODO: DO THE ENCRYPTION OF THE FILE WITH KEY!
            # encryptFile = .....
            file_encrypted = crypto.encrypt_file(file_path, 'temp_server/file_sym.enc')
            print(f"文件已加密: {file_encrypted},path={file_path}")
            # TODO: DO THE ENCRYPTION OF THE KEY!
            
            return file_encrypted, True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def asy_upload(self, uploadName, fileName):
        """使用非对称加密上传文件到服务器"""
        try:
            # 读取加密后的文件
            with open(uploadName, 'rb') as f:
                encrypted_data = f.read()
            
            # 分块大小 - 每次发送1MB
            chunk_size = 1024 * 1024
            total_chunks = (len(encrypted_data) + chunk_size - 1) // chunk_size
            
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((self.server_host, self.server_port))
                
                # 发送上传文件初始请求
                init_request = {
                    'type': 'init_upload',
                    'username': self.current_user['username'],
                    'file_name': fileName,
                    'total_chunks': total_chunks,
                    'file_size': len(encrypted_data)
                }
                client_socket.send(json.dumps(init_request).encode('utf-8'))
                
                # 接收响应
                response = client_socket.recv(4096).decode('utf-8')
                result = json.loads(response)
                
                if not result['success']:
                    messagebox.showerror("Error", f"初始化文件上传失败: {result.get('error', '未知错误')}")
                    return False
                
                # 关闭初始连接
                client_socket.close()
                
                # 分块上传
                for i in range(total_chunks):
                    # 创建新的连接
                    chunk_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        chunk_socket.connect((self.server_host, self.server_port))
                        
                        # 计算当前块的数据
                        start = i * chunk_size
                        end = min(start + chunk_size, len(encrypted_data))
                        chunk_data = encrypted_data[start:end]
                        
                        # 发送块数据
                        chunk_request = {
                            'type': 'upload_chunk',
                            'username': self.current_user['username'],
                            'file_name': fileName,
                            'chunk_index': i,
                            'total_chunks': total_chunks,
                            'chunk_data': base64.b64encode(chunk_data).decode('utf-8')
                        }
                        chunk_socket.send(json.dumps(chunk_request).encode('utf-8'))
                        
                        # 接收响应
                        chunk_response = chunk_socket.recv(4096).decode('utf-8')
                        chunk_result = json.loads(chunk_response)
                        
                        if not chunk_result['success']:
                            messagebox.showerror("Error", f"上传文件块 {i+1}/{total_chunks} 失败: {chunk_result.get('error', '未知错误')}")
                            return False
                    finally:
                        chunk_socket.close()
                
                # 完成上传 - 发送完成请求
                complete_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    complete_socket.connect((self.server_host, self.server_port))
                    
                    complete_request = {
                        'type': 'complete_upload',
                        'username': self.current_user['username'],
                        'file_name': fileName
                    }
                    complete_socket.send(json.dumps(complete_request).encode('utf-8'))
                    
                    # 接收响应
                    complete_response = complete_socket.recv(4096).decode('utf-8')
                    complete_result = json.loads(complete_response)
                    
                    if complete_result['success']:
                        messagebox.showinfo("Success", "文件上传成功")
                        return True
                    else:
                        messagebox.showerror("Error", f"完成文件上传失败: {complete_result.get('error', '未知错误')}")
                        return False
                finally:
                    complete_socket.close()
                
            except Exception as e:
                messagebox.showerror("Error", f"文件上传过程中发生错误: {str(e)}")
                return False
            finally:
                # 确保连接关闭
                if client_socket:
                    client_socket.close()
                
        except Exception as e:
            messagebox.showerror("Error", f"文件上传过程中发生错误: {str(e)}")
            return False

        # TODO: DO THE DECRYPTION OF THE FILE!
        username=self.current_user['username']
        config = CryptoConfig(
            crypto_type=CryptoType.ASYMMETRIC,
                            
            private_key_file=f"{username}_private_key.pem",
            public_key_file=f"{username}_public_key.pem",
            private_key_password="test_password",
            add_signature=True
        )
        crypto = CryptoUtils(config)

        private_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, f"{username}_private_key.pem"))
        public_key_path = os.path.abspath(os.path.join(crypto.key_manager.keys_dir, f"{username}_public_key.pem"))
        # TODO: decrypt data with asy key
        # decryptFile= .....
        print(f"使用私钥文件: {private_key_path}")
        print(f"使用公钥文件: {public_key_path}")


        def get_original_filename(encrypted_file):
            with open(encrypted_file, 'rb') as f:
                try:
                    metadata_length_bytes = f.read(4)
                    metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                    metadata_bytes = f.read(metadata_length)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    if 'original_filename' in metadata:
                        return metadata['original_filename']
                except:
                    pass
            return None
        file_decrypted = crypto.decrypt_file(uploadName)
        print(f"解密后文件路径: {file_decrypted}，文件名：{get_original_filename(uploadName)}")        
        
        with open(file_decrypted, 'rb') as decryptFile:
            data = decryptFile.read()
            self.uploadFile(data, fileName)

    def asy_download(self, fileName):
        username = self.current_user['username'] 
        # 确定文件路径
        if self.current_user['role'] == 'admin' and '/' in fileName:
            folder, name = fileName.split('/', 1)
            file_path = fileName
        elif self.current_user['role'] == 'admin':
            file_path = 'data/' + fileName
        else:
            file_path = 'data/' + self.current_user['username'] + '/' + fileName
        

        
        file_path = file_path.replace("\\", "/")
        print(file_path)
        print(fileName+'验证是否正确')
        try:
            # 确保源文件存在
            #if not os.path.exists(file_path):
            #    messagebox.showerror("Error", f"Source file does not exist: {fileName}")
            #    return '', False
            #if file_path=='data/file_hashes.json' or file_path=='data/users.csv':
            #    messagebox.showerror("Error", f"You cannot download system file! : {fileName}")
            #   return '', False

            # 向服务器发送完整性检查请求
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.server_host, self.server_port))
                
                # 发送完整性检查请求
                check_request = {
                    'type': 'check_integrity'
                }
                client_socket.send(json.dumps(check_request).encode('utf-8'))
                
                # 接收响应
                response = client_socket.recv(1024).decode('utf-8')
                result = json.loads(response)
                
                if not result['success']:
                    messagebox.showerror("Error", "Failed to verify file integrity")
                    return '', False
                
                # 检查特定文件的完整性结果
                verification_results = result.get('verification_results', {})
                if file_path not in verification_results or not verification_results[file_path]:
                    messagebox.showerror("Error", f"Integrity checks failed: {fileName}")
                    return '', False
                
                client_socket.close()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to verify file integrity: {str(e)}")
                return '', False

            # 完整性验证通过后，发送下载请求
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.server_host, self.server_port))
                
                # 发送下载请求
                download_request = {
                    'type': 'download_file',
                    'file_path': file_path,
                    'username': username
                }
                client_socket.send(json.dumps(download_request).encode('utf-8'))
                
                # 接收响应
                print('debug6')
                response = b''
                while True:
                    chunk = client_socket.recv(8192)  # 增大缓冲区
                    if not chunk:
                        break
                    response += chunk
                    # 尝试解析,如果成功就退出循环
                    try:
                        result = json.loads(response.decode('utf-8'))
                        break
                    except json.JSONDecodeError:
                        continue
                        
                print('debug1')
                if not result['success']:
                    messagebox.showerror("Error", f"Failed to download file: {result.get('error', '未知错误')}")
                    return '', False
                print('debug2')
                # 确保temp_server目录存在
                if not os.path.exists('temp_server'):
                    os.makedirs('temp_server')
                print('debug3')    
                # 保存加密后的文件
                encrypted_data = base64.b64decode(result['encrypted_file'])
                encrypted_file_path = 'temp_server/file_asym.enc'
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_data)
                print('debug4')    
                return encrypted_file_path, True
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download file: {str(e)}")
                return '', False
            finally:
                client_socket.close()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")
            return '', False

    def uploadFile(self, fileData, fileName):

        # 服务器存储路径
        if self.current_user['role'] == 'admin':
            print(f'admin now1:{fileName}')
            dir_path = 'data/'
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            saved_path = dir_path+fileName;
            print(f'admin now2:{saved_path}')
        else:
            dir_path = 'data/' + self.current_user['username'] + '/'
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            saved_path = dir_path + fileName

        file_hash = HashController.calculate_file_hash(fileData)
        data_dir = "data/"

        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        # 生成哈希文件 - 修改为存储在data目录
        hash_file = data_dir + "file_hashes.json"
        if os.path.exists(hash_file):
            # 如果哈希文件已存在，更新它
            try:
                with open(hash_file, 'r') as f:
                    hash_data = json.load(f)
                    algorithm = hash_data.get('algorithm', 'sha256')
                    hashes = hash_data.get('hashes', {})
            except:
                algorithm = 'sha256'
                hashes = {}

            # 更新哈希值
            hashes[saved_path] = file_hash

            with open(hash_file, 'w') as f:
                json.dump({
                    'algorithm': algorithm,
                    'hashes': hashes
                }, f, indent=4)
        else:
            # 如果哈希文件不存在，创建一个新的
            HashController.generate_hash_file("data/", hash_file)
        # 保存文件本身
        with open(saved_path, 'wb') as file:
            print(f'admin now3:{saved_path}')
            file.write(fileData)

    def getFileList(self):
        """获取文件列表"""
        try:
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送获取文件列表请求
            request_data = {
                'type': 'get_files',
                'username': self.current_user['username'],
                'role': self.current_user['role']
            }
            client_socket.send(json.dumps(request_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            result = json.loads(response)
            
            if result['success']:
                return result['files']
            else:
                return []
                
        except Exception as e:
            print(f"获取文件列表错误: {str(e)}")
            return []
        finally:
            client_socket.close()
        dir_path = 'data/' + self.current_user['username']
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        list = []
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        try:
            files = os.listdir(dir_path)
            for file in files:
                if os.path.isfile(os.path.join(dir_path, file)):
                    list.append(file)
            return list
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file list: {str(e)}")

    #TODO:PLACE HOLDER FUNCTION
    def downloadFile(self, fileName):
        # 确定文件路径
        if self.current_user['role'] == 'admin' and '/' in fileName:
            # 管理员下载子文件夹中的文件
            folder, name = fileName.split('/', 1)
            file_path = os.path.join(Path(__file__).parent.parent, "upload_file", folder, name)
        elif self.current_user['role'] == 'admin':
            # 管理员下载根目录中的文件
            file_path = 'data/' + fileName
        else:
            # 普通用户下载自己文件夹中的文件
            file_path = 'data/' + self.current_user['username'] + '/' + fileName

        try:
            # 确保源文件存在
            if not os.path.exists(file_path):
                messagebox.showerror("Error", f"Source file does not exist: {fileName}")
                return '', False

            with open(file_path, 'rb') as file:
                original_content = file.read()
            file_hash = HashController.calculate_file_hash(original_content)
            hash_file = "data/file_hashes.json"
            try:
                with open(hash_file, 'r') as f:
                    hash_data = json.load(f)
                    algorithm = hash_data.get('algorithm', 'sha256')
                    hashes = hash_data.get('hashes', {})
            except:
                algorithm = 'sha256'
                hashes = {}

            src_hash = hash_data['hashes'][file_path]

            if src_hash != file_hash:
                messagebox.showerror("Error", f"Integrity checks failed: {fileName}")
                return [], False
            return original_content, True

        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def get_FileWithDirList(self, path):
        try:
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送获取文件列表请求
            request_data = {
                'type': 'get_files',
                'username': self.current_user['username'],
                'role': self.current_user['role']
            }
            client_socket.send(json.dumps(request_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            result = json.loads(response)
            
            if result['success']:
                return result['files']
            else:
                return []
                
        except Exception as e:
            print(f"获取文件列表错误: {str(e)}")
            return []
        finally:
            client_socket.close()
        
        dir_path = path
        list = []
        try:
            # 获取当前目录下的所有项目
            items = os.listdir(dir_path)
            # 先添加文件夹
            for item in sorted(items):
                item_path = os.path.join(dir_path, item)
                if os.path.isdir(item_path):
                    list.append(f"📁 {item}")

            # 再添加文件
            for item in sorted(items):
                item_path = os.path.join(dir_path, item)
                if os.path.isfile(item_path):
                    list.append(f"📄 {item}")
            return list;
        except Exception as e:
            messagebox.showerror("错误", f"加载文件列表失败: {str(e)}")

    def check_file_integrity(self):
        """检查文件完整性并提供更新选项"""
        try:
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送检查文件完整性请求
            request_data = {
                'type': 'check_integrity',
                'username': self.current_user['username'],
                'role': self.current_user['role']
            }
            client_socket.send(json.dumps(request_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            result = json.loads(response)
            
            if not result['success']:
                messagebox.showerror("错误", f"检查文件完整性失败: {result.get('error', '未知错误')}")
                return
                
            # 获取验证结果
            verification_results = result.get('verification_results', {})
            
            # 统计修改、添加和删除的文件
            modified_files = []
            new_files = []
            missing_files = []
            
            for file_path, result in verification_results.items():
                if result.get('exists', False) and not result.get('valid', True):
                    modified_files.append(file_path)
                elif result.get('new_file', False):
                    new_files.append(file_path)
                elif not result.get('exists', True):
                    missing_files.append(file_path)
                    
            if not modified_files and not new_files and not missing_files:
                messagebox.showinfo("完整性检查", "所有文件完整性检查通过！")
                return
                
            # 构建消息
            message = "文件完整性检查结果:\n\n"
            
            if modified_files:
                message += "已修改的文件:\n"
                for file in modified_files:
                    message += f"- {file}\n"
                message += "\n"
                
            if new_files:
                message += "新增的文件:\n"
                for file in new_files:
                    message += f"- {file}\n"
                message += "\n"
                
            if missing_files:
                message += "丢失的文件:\n"
                for file in missing_files:
                    message += f"- {file}\n"
                message += "\n"
                
            message += "是否更新哈希值文件？"
            
            result = messagebox.askyesno("完整性检查结果", message)
            if result:
                try:
                # 发送更新哈希文件请求
                    new_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    new_client_socket.connect((self.server_host, self.server_port))
                
                    update_request = {
                        'type': 'update_hash_file',
                        'username': self.current_user['username'],
                        'role': self.current_user['role']
                    }
                    new_client_socket.send(json.dumps(update_request).encode('utf-8'))
                
                    # 接收更新响应
                    update_response = new_client_socket.recv(1024).decode('utf-8')
                    update_result = json.loads(update_response)
                
                    if update_result['success']:
                        messagebox.showinfo("成功", "哈希值文件已更新")
                    else:
                        messagebox.showerror("错误", f"更新哈希值文件失败: {update_result.get('error', '未知错误')}")
                finally:
                    new_client_socket.close()
                    
        except Exception as e:
            messagebox.showerror("错误", f"检查文件完整性时出错: {str(e)}")


    def check_file_integrity_on_login(self):
        """登录时检查文件完整性"""
        data_dir = 'data/'

        # 确保data目录存在
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        hash_file = 'data/file_hashes.json'

        if not os.path.exists(hash_file):
            result = messagebox.askyesno("Hash file not found", "Hash file does not exist, create a new hash file?")
            if result:
                HashController.generate_hash_file(data_dir, hash_file)
                messagebox.showinfo("Success", "Hash file created successfully")
            return

        try:
            all_passed, verification_results = HashController.verify_directory(data_dir, hash_file)

            # 统计修改、添加和删除的文件
            modified_files = []
            new_files = []
            missing_files = []

            for file_path, result in verification_results.items():
                if result.get('exists', False) and not result.get('valid', True):
                    modified_files.append(file_path)
                elif result.get('new_file', False):
                    new_files.append(file_path)
                elif not result.get('exists', True):
                    missing_files.append(file_path)

            if all_passed and not new_files and not missing_files:
                return

            # 构建消息
            message = "Login integrity check found the following issues:\n\n"

            if modified_files:
                message += "Modified files:\n"
                for file in modified_files:
                    message += f"- {file}\n"
                message += "\n"

            if new_files:
                message += "New files:\n"
                for file in new_files:
                    message += f"- {file}\n"
                message += "\n"

            if missing_files:
                message += "Missing files:\n"
                for file in missing_files:
                    message += f"- {file}\n"
                message += "\n"

            message += "Update hash file?"

            result = messagebox.askyesno("Login Integrity Check", message)
            if result:
                HashController.generate_hash_file(data_dir, hash_file)
                messagebox.showinfo("Success", "Hash file updated")

        except Exception as e:
            messagebox.showerror("Error", f"Error checking file integrity at login: {str(e)}")

    def deleteFile(self, file_path):
        """删除文件并更新哈希值文件"""
        try:
            # 确保文件存在
            #if not os.path.exists(file_path):
            #   messagebox.showerror("Error", f"文件不存在: {file_path}")
            #    return False
                
            # 检查是否是系统文件
            if file_path == 'data/file_hashes.json' or file_path == 'data/users.csv':
                messagebox.showerror("Error", f"不能删除系统文件: {file_path}")
                return False

            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送删除文件请求
            request_data = {
                'type': 'delete_file',
                'username': self.current_user['username'],
                'role': self.current_user['role'],
                'file_path': file_path
            }
            client_socket.send(json.dumps(request_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            result = json.loads(response)
            
            if result['success']:
                # 询问是否更新哈希值文件
                self.updateHashFile()
                return True
            else:
                messagebox.showerror("Error", result.get('error', '删除文件失败'))
                return False
                
        except Exception as e:
            messagebox.showerror("Error", f"删除文件失败: {str(e)}")
            return False
        finally:
            client_socket.close()

    def updateHashFile(self):
        """更新哈希值文件"""
        try:
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送更新哈希值文件请求
            request_data = {
                'type': 'update_hash_file',
                'username': self.current_user['username'],
                'role': self.current_user['role']
            }
            client_socket.send(json.dumps(request_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            result = json.loads(response)
            
            if result['success']:
                messagebox.showinfo("成功", "哈希值文件已更新")
                return True
            else:
                messagebox.showerror("Error", result.get('error', '更新哈希值文件失败'))
                return False
                
        except Exception as e:
            messagebox.showerror("Error", f"更新哈希值文件失败: {str(e)}")
            return False
        finally:
            client_socket.close()

    def deleteFolder(self, path):
        try:
            shutil.rmtree(path)
            data_dir = 'data/'
            hash_file = 'data/file_hashes.json'
            if os.path.exists(hash_file):
                result = messagebox.askyesno("Update Hash File", "File deleted, update hash file?")
                if result:
                    HashController.generate_hash_file(data_dir, hash_file)
                    messagebox.showinfo("成功", "哈希值文件已更新")
        except Exception as e:
            messagebox.showerror("Error", f"Filed to delete: {str(e)}")
