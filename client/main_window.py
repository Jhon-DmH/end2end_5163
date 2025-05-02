import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import shutil
import json
import socket
from pathlib import Path
from controller.userController import UserController
from controller.fileController import FileController
from utils.asymmetric_crypto import AsymmetricCrypto
from utils.crypto_utils import CryptoConfig, CryptoType, CryptoUtils
from utils.symmetric_crypto import SymmetricCrypto
import re
# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

# 导入哈希验证工具
from utils.hash_utils import HashVerifier


class MainWindow:
    def __init__(self, root, user, login_window,mode):
        self.root = root
        self.user = user
        self.role = user['role']
        self.login_window = login_window
        self.server_host = 'localhost'
        self.server_port = 5163
        #加密解密初始化
        self.cryptoMode=mode
        # 设置窗口标题和大小
        self.root.title(f"Secure File Transfer System - User: {user['username']}")
        self.root.geometry("800x500")

        # 确保关闭主窗口时也关闭登录窗口
        self.root.protocol("WM_DELETE_WINDOW", self.logout)

        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建文件列表框架
        file_list_frame = ttk.LabelFrame(self.main_frame, text="File List")
        file_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建文件列表
        self.file_listbox = tk.Listbox(file_list_frame, width=50, height=20)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(file_list_frame, orient="vertical", command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)

        # 创建按钮框架
        button_frame = ttk.Frame(self.main_frame, padding="10")
        button_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

        # 刷新按钮
        self.refresh_button = ttk.Button(button_frame, text="Refresh", command=self.refresh_file_list)
        self.refresh_button.pack(fill=tk.X, pady=10)

        # 上传按钮
        self.upload_button = ttk.Button(button_frame, text="Upload File", command=self.upload_file)
        self.upload_button.pack(fill=tk.X, pady=10)

        # 下载按钮
        self.download_button = ttk.Button(button_frame, text="Download File", command=self.download_file)
        self.download_button.pack(fill=tk.X, pady=10)

        # 登出按钮
        self.logout_button = ttk.Button(button_frame, text="Logout", command=self.logout)
        self.logout_button.pack(fill=tk.X, pady=10)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set(f"Logged in as: {user['username']} ({user['role']})")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        crypto_1 = CryptoUtils()
                                     
        username = self.user['username'] 
        keys = crypto_1.generate_keys(
            symmetric_key_file=f"{username}_symmetric_key.key",
            private_key_file=f"{username}_private_key.pem",
            public_key_file=f"{username}_public_key.pem",
            password="test_password"
        )  
                    
        print("\n密钥已生成:")
        if 'symmetric_key' in keys:
            print(f"- 对称密钥文件: {keys['symmetric_key']['file_path']}")
    
        if 'asymmetric_keys' in keys:
            print(f"- 私钥文件: {keys['asymmetric_keys']['private_path']}")
            print(f"- 公钥文件: {keys['asymmetric_keys']['public_path']}")

 
        # Controller初始化
        self.fileController = FileController(user)

        # 加载文件列表
        self.refresh_file_list()

    def refresh_file_list(self):
        """刷新文件列表"""
        # 清空列表
        self.file_listbox.delete(0, tk.END)
        """刷新文件列表"""
        # 清空列表
        self.file_listbox.delete(0, tk.END)
        list = self.fileController.getFileList()
        # 显示所有文件
        for file in list:
            self.file_listbox.insert(tk.END, file)

    def upload_file(self):
        """上传文件功能"""

        # 打开文件选择对话框
        file_path = filedialog.askopenfilename(
            title="Select a file to upload",
            filetypes=[("All Files", "*.*")]
        )

        if file_path:
            # 获取服务器公钥
            # 获取服务器公钥
            try:
                # 创建Socket连接
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    client_socket.connect((self.server_host, self.server_port))
                    
                    # 发送获取服务器公钥请求
                    request_data = {
                        'type': 'get_server_public_key',
                        'username': self.user['username']
                    }
                    client_socket.send(json.dumps(request_data).encode('utf-8'))
                    
                    # 接收响应
                    response = client_socket.recv(4096).decode('utf-8')
                    result = json.loads(response)
                    
                    if not result['success']:
                        messagebox.showerror("Error", f"获取服务器公钥失败: {result.get('error', '未知错误')}")
                        return
                    
                    # 确保keys目录存在
                    keys_dir = 'keys'
                    if not os.path.exists(keys_dir):
                        os.makedirs(keys_dir)
                    
                    # 保存服务器公钥
                    server_public_key = result['public_key']
                    with open(os.path.join(keys_dir, "server_public_key.pem"), 'w') as f:
                        f.write(server_public_key)
                finally:
                    # 确保无论如何都关闭连接
                    client_socket.close()
                    
            except Exception as e:
                messagebox.showerror("Error", f"获取服务器公钥失败: {str(e)}")
                return
                
            file_name = os.path.basename(file_path)
            #messagebox.showinfo("Upload", f"Selected file: {file_name}\n\nSimulating upload...")
            try:
                fileData = []
                with open(file_path, 'rb') as file:
                    fileData = file.read()
                    
                    username = self.user['username']   
                    


                    # TODO: IMPLEMENT THE SYMMETRIC!
                    if self.cryptoMode == CryptoType.SYMMETRIC:
                        # TODO: GENERATE KEY
                        # key=...
                        config = CryptoConfig(
                            crypto_type=CryptoType.SYMMETRIC,
                            symmetric_key_file=f"{username}_symmetric_key.key",
                            symmetric_key_password="test_password"
                        )
                        crypto = CryptoUtils(config)
                        # TODO: ENCRYPT FILE WITH KEY
                        # encryptedData =...
                        file_encrypted = crypto.encrypt_file(file_path, 'temp_client/file_sym.enc')
                        print(f"文件已加密: {file_encrypted},path={file_path}")

                        encryptedData = fileData
                        # TODO: ENCRYPT KEY
                        # en_key=...
                        # TODO: CHANGE TO SOCKET!
                        self.fileController.sy_upload(file_encrypted, file_name)
                    # TODO: IMPLEMENT THE ASYMMETRIC!
                    
                    elif self.cryptoMode == CryptoType.ASYMMETRIC:
                        # TODO: ENCRYPT FILE WITH KEY
                        # encryptedData =...
                        config = CryptoConfig(
                            crypto_type=CryptoType.ASYMMETRIC,
                            
                            #private_key_file=f"{username}_private_key.pem",
                            public_key_file=f"server_public_key.pem",
                            private_key_password="test_password",
                            add_signature=True
                        )
                        crypto = CryptoUtils(config)
                        # 加密文件
                        file_encrypted = crypto.encrypt_file(file_path, 'temp_client/file_asym.enc')
                        print(f"文件已加密: {file_encrypted},path={file_path}")
                        
                        # 上传加密后的文件
                        success = self.fileController.asy_upload(file_encrypted, file_name)
                        if success:
                            self.refresh_file_list()
                    else:
                        self.fileController.upload(fileData, file_name)

                self.refresh_file_list()
                self.status_var.set(f"File uploaded: {file_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload file: {str(e)}")

        self.refresh_file_list()
        self.status_var.set(f"File uploaded: {file_name} (Integrity verified)")

    def download_file(self):
        """下载文件功能"""
        # 获取选中的文件
        selected = self.file_listbox.curselection()
        username = self.user['username']
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to download")
            return

        # 获取选中的文件名
        file_name = self.file_listbox.get(selected[0])
        print(f"整理前：{file_name}")
        def clean_path(path):
        # 拆分路径和文件名
            dir_path, filename = os.path.split(path)

            # 去除文件名前的表情符号和空格
            cleaned_filename = re.sub(r'^[^\w\s]*\s*', '', filename)

            # 拼接干净的路径
            cleaned_path = os.path.join(dir_path, cleaned_filename)

            return cleaned_path

        file_name = clean_path(file_name)
        print(f"整理后：{file_name}")
        # 发送公钥到服务器
        try:
            # 读取公钥文件
            public_key_path = os.path.join('keys', f"{username}_public_key.pem")
            with open(public_key_path, 'r') as f:
                public_key = f.read()
            
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送公钥传输请求
            key_data = {
                'type': 'transfer_public_key',
                'username': username,
                'public_key': public_key
            }
            client_socket.send(json.dumps(key_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            result = json.loads(response)
            
            if not result['success']:
                messagebox.showerror("Error", f"公钥传输失败: {result.get('error', '未知错误')}")
                return
                
            client_socket.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"公钥传输失败: {str(e)}")
            return

        # GETTING THE FILE
        # TODO: IMPLEMENT THE SYMMETRIC!
        if self.cryptoMode == CryptoType.SYMMETRIC:
            # TODO: CHANGE TO SOCKET
            filePath, result = self.fileController.sy_download(file_name)
            # TODO: DECRYPT THE KEY
            config = CryptoConfig(
                crypto_type=CryptoType.SYMMETRIC,
                symmetric_key_file=f"{username}_symmetric_key.key",
                symmetric_key_password="test_password"
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

            file_decrypted = crypto.decrypt_file(filePath)
            # de_key=....
            # TODO: DECRYPT THE FILE
            # decryptedData= ...

            #decryptedData = fileData

        # TODO: IMPLEMENT THE ASYMMETRIC!
        elif self.cryptoMode == CryptoType.ASYMMETRIC:
            # TODO: CHANGE TO SOCKET
            print(file_name+'用户目标路径')
            filePath, result = self.fileController.asy_download(file_name)
            # TODO: USE Private_KEY TO DECRYPT DATA
            # decryptedData= ...
        
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
            print(f"使用私钥文件: {private_key_path}")
            print(f"使用公钥文件: {public_key_path}")
            file_decrypted = crypto.decrypt_file(filePath)

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
            print(f"解密后文件路径: {file_decrypted}，文件名：{get_original_filename(filePath)}")        
            #decryptedData = fileData
        else:
            # TODO: CHANGE TO SOCKET
            file_decrypted, result = self.fileController.asy_download(file_name)

        if not result:
            self.status_var.set("Error when fetching file:" +{file_name})
            return


        with open(file_decrypted, 'rb') as decryptFile:
            decryptedData = decryptFile.read()
            download_path = filedialog.askdirectory(
                title="Select a directory to download to"
            )

            if not os.path.exists(download_path):
                os.makedirs(download_path)

            dest_path = download_path+'/'+file_name
            if os.path.exists(dest_path):
                base_name, ext = os.path.splitext(file_name)
                dest_path = download_path+'/'+base_name+'_'+self.user['username']+ext
            try:
                with open(dest_path, 'wb') as file:
                    file.write(decryptedData)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to saved file: {str(e)}")


    def logout(self):
        """登出功能"""
        # 关闭主窗口
        self.root.destroy()

        # 显示登录窗口
        self.login_window.root.deiconify()

        # 清空登录窗口的用户名和密码
        self.login_window.username_var.set("")
        self.login_window.password_var.set("")
        self.login_window.status_var.set("")
