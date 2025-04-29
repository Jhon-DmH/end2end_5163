import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

class MainWindow:
    def __init__(self, root, username, role, login_window):
        self.root = root
        self.username = username
        self.role = role
        self.login_window = login_window
        
        # 设置窗口标题和大小
        self.root.title(f"Secure File Transfer System - User: {username}")
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
        self.status_var.set(f"Logged in as: {username} ({role})")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 加载文件列表
        self.refresh_file_list()
    
    def refresh_file_list(self):
        """刷新文件列表"""
        # 清空列表
        self.file_listbox.delete(0, tk.END)
        
        # 获取upload_file目录的路径
        upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
        
        # 确保目录存在
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # 获取目录中的文件
        try:
            files = os.listdir(upload_dir)
            for file in files:
                if os.path.isfile(os.path.join(upload_dir, file)):
                    self.file_listbox.insert(tk.END, file)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file list: {str(e)}")
    
    def upload_file(self):
        """上传文件功能"""
        # 打开文件选择对话框
        file_path = filedialog.askopenfilename(
            title="Select a file to upload",
            filetypes=[("All Files", "*.*")]
        )
        
        if file_path:
            # 获取文件名
            file_name = os.path.basename(file_path)
            
            # 模拟上传成功
            messagebox.showinfo("Upload", f"Selected file: {file_name}\n\nSimulating upload...")
            
            # 实际上，这里应该实现文件复制到upload_file目录
            try:
                # 获取upload_file目录的路径
                upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
                
                # 确保目录存在
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir)
                
                # 复制文件
                import shutil
                dest_path = os.path.join(upload_dir, file_name)
                shutil.copy2(file_path, dest_path)
                
                # 刷新文件列表
                self.refresh_file_list()
                
                # 更新状态栏
                self.status_var.set(f"File uploaded: {file_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload file: {str(e)}")
    
    def download_file(self):
        """下载文件功能"""
        # 获取选中的文件
        selected = self.file_listbox.curselection()
        
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to download")
            return
        
        # 获取选中的文件名
        file_name = self.file_listbox.get(selected[0])
        
        # 模拟下载
        messagebox.showinfo("Download", f"Selected file: {file_name}\n\nSimulating download...")
        
        # 更新状态栏
        self.status_var.set(f"File downloaded: {file_name}")
    
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