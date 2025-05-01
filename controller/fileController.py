import os
import shutil
from tkinter import messagebox
from pathlib import Path
from utils.encryption import Cryptor
from controller.hashController import HashController
import json


class FileController:

    def __init__(self, user):
        self.current_user = user
        self.my_Cryptor = Cryptor("AES")
        self.as_key = ''
        self.sm_key = ''

    def sy_upload(self, file, fileName, key):
        # TODO: DO THE DECRYPTION OF THE KEY!
        de_key = key
        # TODO: DO THE DECRYPTION OF THE FILE!
        # TODO: decrypt data with sy key
        # decryptFile= .....
        decryptFile = file
        self.uploadFile(decryptFile, fileName)

    def sy_download(self, fileName):
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
                return [], [], False

            key = {}
            # TODO: DO THE ENCRYPTION OF THE FILE WITH KEY!
            # encryptFile = .....
            encryptFile = original_content
            # TODO: DO THE ENCRYPTION OF THE KEY!
            en_key = key
            return encryptFile, en_key, True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def asy_upload(self, file, fileName):

        # TODO: DO THE DECRYPTION OF THE FILE!
        # TODO: decrypt data with asy key
        # decryptFile= .....
        decryptFile = file
        self.uploadFile(decryptFile, fileName)

    def asy_downloadFile(self, fileName):

        # 确定文件路径
        if self.current_user['role'] == 'admin' and '/' in fileName:
            # 管理员下载子文件夹中的文件
            folder, name = fileName.split('/', 1)
            file_path = fileName
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
                return [], False

            # TODO: encryp data with public key
            # encryptFile = .....
            encryptFile = original_content
            return encryptFile, True

        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def uploadFile(self, fileData, fileName):

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
            file.write(fileData)

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
                HashController.generate_hash_file(data_dir, hash_file)
                messagebox.showinfo("成功", "哈希值文件已更新")

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

    def deleteFile(self, path):
        try:
            os.remove(path)

            # 更新哈希文件
            data_dir = 'data/'
            hash_file = 'data/file_hashes.json'
            if os.path.exists(hash_file):
                result = messagebox.askyesno("Update Hash File", "File deleted, update hash file?")
                if result:
                    HashController.generate_hash_file(data_dir, hash_file)
                    messagebox.showinfo("成功", "哈希值文件已更新")
        except Exception as e:
            messagebox.showerror("Error", f"Filed to delete: {str(e)}")

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
