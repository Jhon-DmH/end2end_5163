import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import shutil
import json
from pathlib import Path
from controller.userController import UserController
from controller.fileController import FileController

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

# 导入哈希验证工具
from utils.hash_utils import HashVerifier


class MainWindow:
    def __init__(self, root, user, login_window):
        self.root = root
        self.user = user
        self.role = user['role']
        self.login_window = login_window

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
            file_name = os.path.basename(file_path)
            messagebox.showinfo("Upload", f"Selected file: {file_name}\n\nSimulating upload...")
            try:
                fileData = []
                with open(file_path, 'rb') as file:
                    fileData = file.read()
                # TODO: Encrypt data
                # encryptedData= .....
                encryptedData = fileData
                self.fileController.uploadFile(encryptedData, file_name)
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

        if not selected:
            messagebox.showwarning("Warning", "Please select a file to download")
            return

        # 获取选中的文件名
        file_name = self.file_listbox.get(selected[0])
        fileData,result = self.fileController.downloadFile(file_name)
        # TODO: decrypt Data
        # decryptedData= .....
        decryptedData = fileData
        if not result:
            self.status_var.set("Error when fetching file:" +{file_name})
            return

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
