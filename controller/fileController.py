import os
from tkinter import filedialog, messagebox
from pathlib import Path
from utils.message import result
from utils.encryption import Cryptor
from utils.hash_utils import HashVerifier
import json


class FileController:

    def __init__(self, user):
        self.current_user = user
        self.my_Cryptor = Cryptor("AES")

    def uploadFile(self, file, fileName):

        # TODO: decrypt data
        # decryptFile= .....
        decryptFile = file

        # 服务器存储路径
        if self.current_user['role'] == 'admin':
            dir_path = 'data/'
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            saved_path = dir_path + fileName;
        else:
            dir_path = 'data/' + self.current_user['username'] + '/'
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            saved_path = dir_path + fileName

        file_hash = HashVerifier.calculate_file_hash(file)
        data_dir = "data/"
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        # 生成哈希文件 - 修改为存储在data目录
        hash_file = data_dir  + "file_hashes.json"
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
            HashVerifier.generate_hash_file("data/", hash_file)

        with open(saved_path, 'wb') as file:
            file.write(decryptFile)

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
                return '',False

            with open(file_path, 'rb') as file:
                original_content = file.read()
            file_hash = HashVerifier.calculate_file_hash(original_content)
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

            if src_hash!=file_hash:
                messagebox.showerror("Error", f"Integrity checks failed: {fileName}")
                return [],False

            # TODO: encryp data
            # encryptFile = .....
            encryptFile = original_content
            return encryptFile,True

        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def deleteFile(self, file, user):
        # 执行删除操作
        try:
            # 获取上传目录路径
            file_path = "data/" + user['username'] + file;
            # 检查文件是否存在
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"文件 '{file}' 不存在")
            # 删除文件
            os.remove(file_path)
            # 更新界面
            self.refresh_file_list()
            self.status_var.set(f"已删除文件: {file}")
            messagebox.showinfo("成功", "文件删除成功")
        except Exception as e:
            messagebox.showerror("错误", f"删除失败: {str(e)}")
        return

    def getFileList(self):
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

    def getRootFileList(self, ):
        return;
