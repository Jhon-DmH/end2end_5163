import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import shutil
import json
from pathlib import Path

from controller.fileController import FileController
from utils.asymmetric_crypto import AsymmetricCrypto
from utils.crypto_utils import CryptoType, CryptoConfig, CryptoUtils
from utils.symmetric_crypto import SymmetricCrypto

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

# 导入哈希验证工具
from utils.hash_utils import HashVerifier


class AdminWindow:
    def __init__(self, root, user, login_window, mode):
        self.root = root
        self.username = user
        self.login_window = login_window
        self.current_path = 'data'
        self.base_path = self.current_path  # 基础路径，不允许回到这个路径之上
        self.cryptoMode = mode

        # Controller初始化
        self.fileController = FileController(user)
        # 设置窗口标题和大小
        self.root.title(f"File Management System - Admin: {user['username']}")
        self.root.geometry("900x600")

        # 确保关闭主窗口时也关闭登录窗口
        self.root.protocol("WM_DELETE_WINDOW", self.logout)

        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建顶部导航栏
        nav_frame = ttk.Frame(self.main_frame)
        nav_frame.pack(fill=tk.X, pady=(0, 10))

        # 当前路径显示
        self.path_var = tk.StringVar()
        self.update_path_display()
        ttk.Label(nav_frame, textvariable=self.path_var).pack(side=tk.LEFT)

        # 返回上一级按钮
        self.back_button = ttk.Button(nav_frame, text="Back", command=self.go_back)
        self.back_button.pack(side=tk.RIGHT)

        # 创建文件列表框架
        file_list_frame = ttk.LabelFrame(self.main_frame, text="Files and Folders")
        file_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建文件列表
        self.file_listbox = tk.Listbox(file_list_frame, width=70, height=20, font=("Arial", 10))
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.file_listbox.bind("<Double-1>", self.on_item_double_click)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(file_list_frame, orient="vertical", command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)

        # 创建按钮框架
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        # 刷新按钮
        self.refresh_button = ttk.Button(button_frame, text="Refresh", command=self.refresh_file_list)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        # 上传按钮
        self.upload_button = ttk.Button(button_frame, text="Upload File", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)

        # 下载按钮
        self.download_button = ttk.Button(button_frame, text="Download File", command=self.download_file)
        self.download_button.pack(side=tk.LEFT, padx=5)

        # 删除按钮
        self.delete_button = ttk.Button(button_frame, text="Delete File", command=self.delete_file)
        self.delete_button.pack(side=tk.LEFT, padx=5)

        # 添加检查文件完整性按钮
        self.check_integrity_button = ttk.Button(button_frame, text="Check File Integrity",
                                                 command=self.fileController.check_file_integrity())
        self.check_integrity_button.pack(side=tk.LEFT, padx=5)

        # 登出按钮
        self.logout_button = ttk.Button(button_frame, text="Logout", command=self.logout)
        self.logout_button.pack(side=tk.RIGHT, padx=5)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set(f"Logged in: {user['username']} (Admin)")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        # 登录时检查文件完整性
        self.fileController.check_file_integrity_on_login()
        # 加载文件列表
        self.refresh_file_list(self.current_path)

    def update_path_display(self):
        """更新路径显示"""
        rel_path = os.path.relpath(self.current_path, self.base_path)
        if rel_path == ".":
            display_path = "/"
        else:
            display_path = "/" + rel_path.replace("\\", "/")
        self.path_var.set(f"Current location: {display_path}")

    def refresh_file_list(self, path):
        """刷新文件列表"""
        # 清空列表
        self.file_listbox.delete(0, tk.END)
        list = self.fileController.get_FileWithDirList(path)
        # 显示所有文件
        for file in list:
            self.file_listbox.insert(tk.END, file)

    def on_item_double_click(self, event):
        """双击项目时的处理"""
        # 获取选中的项目
        selected = self.file_listbox.curselection()
        if not selected:
            return

        item_text = self.file_listbox.get(selected[0])

        # 检查是否是文件夹
        if item_text.startswith("📁"):
            folder_name = item_text[2:].strip()  # 移除文件夹图标和空格
            new_path = self.current_path + '/' + folder_name
            if os.path.isdir(new_path):
                self.current_path = new_path
                self.update_path_display()
                self.refresh_file_list(self.current_path)

    def go_back(self):
        """返回上一级目录"""
        # 确保不会超出基础路径
        if os.path.normpath(self.current_path) == os.path.normpath(self.base_path):
            messagebox.showinfo("Notice", "Already in root directory, cannot go back")
            return

        self.current_path = os.path.dirname(self.current_path)
        self.update_path_display()
        self.refresh_file_list(self.current_path)

    def upload_file(self):
        """上传文件功能"""
        # 打开文件选择对话框
        file_path = filedialog.askopenfilename(
            title="Select a file to upload",
            filetypes=[("All Files", "*.*")]
        )

        if file_path:
            file_name = os.path.basename(file_path)
            messagebox.showinfo("Upload", f"Selected file: {file_name}\n\nSimulating upload...")
            try:
                fileData = []
                with open(file_path, 'rb') as file:
                    fileData = file.read()
                # TODO: IMPLEMENT THE SYMMETRIC!
                if self.cryptoMode == CryptoType.SYMMETRIC:
                    # TODO: GENERATE KEY
                    # key=...
                    # TODO: ENCRYPT FILE WITH KEY
                    # encryptedData =...
                    encryptedData = fileData
                    # TODO: ENCRYPT KEY
                    # en_key=...
                    en_key=[]
                    # TODO: CHANGE TO SOCKET!
                    self.fileController.sy_upload(encryptedData,file_name,en_key)
                # TODO: IMPLEMENT THE ASYMMETRIC!
                elif self.cryptoMode == CryptoType.ASYMMETRIC:
                    # TODO: ENCRYPT FILE WITH KEY
                    # encryptedData =...
                    encryptedData = fileData
                    # TODO: CHANGE TO SOCKET!
                    self.fileController.sy_upload(encryptedData, file_name)
                else:
                    self.fileController.upload(fileData, file_name)


                self.refresh_file_list(self.current_path)
                self.status_var.set(f"File uploaded: {file_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload file: {str(e)}")
        self.refresh_file_list()
        self.status_var.set(f"File uploaded: {file_name} (Integrity verified)")

    def download_file(self):
        """下载文件功能"""
        # 获取选中的项目
        selected = self.file_listbox.curselection()

        if not selected:
            messagebox.showwarning("警告", "请选择要下载的文件")
            return

        item_text = self.file_listbox.get(selected[0])

        # 检查是否是文件
        if not item_text.startswith("📄"):
            messagebox.showwarning("警告", "只能下载文件，不能下载文件夹")
            return

        file_name = item_text[2:].strip()  # 移除文件图标和空格
        src_path = self.current_path + '/' + file_name

        # GETTING THE FILE
        # TODO: IMPLEMENT THE SYMMETRIC!
        if self.cryptoMode == CryptoType.SYMMETRIC:
            # TODO: CHANGE TO SOCKET
            fileData, en_key, result = self.fileController.sy_download(src_path)
            # TODO: DECRYPT THE KEY
            # de_key=....
            # TODO: DECRYPT THE FILE
            # decryptedData= ...
            decryptedData = fileData
        # TODO: IMPLEMENT THE ASYMMETRIC!
        elif self.cryptoMode == CryptoType.ASYMMETRIC:
            # TODO: CHANGE TO SOCKET
            fileData, result = self.fileController.asy_download(src_path)
            # TODO: USE Private_KEY TO DECRYPT DATA
            # decryptedData= ...
            decryptedData = fileData
        else:
            # TODO: CHANGE TO SOCKET
            fileData, result = self.fileController.sy_download(src_path)
            decryptedData = fileData

        if not result:
            self.status_var.set("Error when fetching file:" + {file_name})
            return

        download_path = filedialog.askdirectory(
            title="Select a directory to download to"
        )

        dest_path = download_path + '/' + file_name
        if os.path.exists(dest_path):
            base_name, ext = os.path.splitext(file_name)
            dest_path = download_path + '/' + base_name + '_' + self.user['username'] + ext
        try:
            with open(dest_path, 'wb') as file:
                file.write(decryptedData)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to saved file: {str(e)}")

    def delete_file(self):
        """删除文件功能"""
        # 获取选中的项目
        selected = self.file_listbox.curselection()

        if not selected:
            messagebox.showwarning("警告", "请选择要删除的文件或文件夹")
            return

        item_text = self.file_listbox.get(selected[0])

        # 获取文件/文件夹名称
        if item_text.startswith("📁"):
            is_folder = True
            item_name = item_text[2:].strip()  # 移除文件夹图标和空格
        else:
            is_folder = False
            item_name = item_text[2:].strip()  # 移除文件图标和空格

        item_path = self.current_path + '/' + item_name

        # 确认删除
        if is_folder:
            confirm = messagebox.askyesno("确认删除", f"确定要删除文件夹 {item_name} 及其所有内容吗？")
        else:
            confirm = messagebox.askyesno("确认删除", f"确定要删除文件 {item_name} 吗？")

        if confirm:
            try:
                if is_folder:
                    # TODO: CHANGE TO SOCKET
                    self.fileController.deleteFolder(item_path)
                else:
                    # TODO: CHANGE TO SOCKET
                    self.fileController.deleteFile(item_path)
                self.refresh_file_list(self.current_path)
                # 更新状态栏
                if is_folder:
                    self.status_var.set(f"文件夹已删除: {item_name}")
                else:
                    self.status_var.set(f"文件已删除: {item_name}")
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {str(e)}")

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
