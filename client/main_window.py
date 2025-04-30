import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import shutil
from pathlib import Path

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

# 导入哈希验证工具
from utils.hash_utils import HashVerifier

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
        
        try:
            # 根据用户角色决定显示哪些文件
            if self.role == 'admin':
                # 管理员可以看到所有文件
                files = []
                # 获取根目录下的文件
                for item in os.listdir(upload_dir):
                    item_path = os.path.join(upload_dir, item)
                    if os.path.isfile(item_path):
                        files.append(item)
                    
                # 获取所有子文件夹中的文件
                for item in os.listdir(upload_dir):
                    item_path = os.path.join(upload_dir, item)
                    if os.path.isdir(item_path):
                        for sub_file in os.listdir(item_path):
                            sub_file_path = os.path.join(item_path, sub_file)
                            if os.path.isfile(sub_file_path):
                                files.append(f"{item}/{sub_file}")
                
                # 显示所有文件
                for file in files:
                    self.file_listbox.insert(tk.END, file)
            else:
                # 普通用户只能看到自己文件夹中的文件
                user_dir = os.path.join(upload_dir, self.username)
                
                # 确保用户目录存在
                if not os.path.exists(user_dir):
                    os.makedirs(user_dir)
                    
                # 获取用户目录中的文件
                if os.path.exists(user_dir) and os.path.isdir(user_dir):
                    for file in os.listdir(user_dir):
                        file_path = os.path.join(user_dir, file)
                        if os.path.isfile(file_path):
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
            
            try:
                # 获取upload_file目录的路径
                upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
                
                # 确保目录存在
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir)
                
                # 根据用户角色决定文件保存位置
                if self.role == 'admin':
                    # 管理员可以上传到根目录
                    dest_path = os.path.join(upload_dir, file_name)
                    dest_dir = upload_dir
                else:
                    # 普通用户上传到自己的目录
                    user_dir = os.path.join(upload_dir, self.username)
                    if not os.path.exists(user_dir):
                        os.makedirs(user_dir)
                    dest_path = os.path.join(user_dir, file_name)
                    dest_dir = user_dir
                
                # 复制文件
                shutil.copy2(file_path, dest_path)
                
                # 计算文件哈希值
                file_hash = HashVerifier.calculate_file_hash(dest_path)
                
                # 生成哈希文件 - 修改为始终存储在根目录
                hash_file = os.path.join(upload_dir, "file_hashes.json")
                if os.path.exists(hash_file):
                    # 如果哈希文件已存在，更新它
                    with open(hash_file, 'r') as f:
                        try:
                            hash_data = json.load(f)
                            algorithm = hash_data.get('algorithm', 'sha256')
                            hashes = hash_data.get('hashes', {})
                        except:
                            algorithm = 'sha256'
                            hashes = {}
                    
                    # 更新哈希值 - 使用相对于根目录的路径
                    rel_path = os.path.relpath(dest_path, upload_dir)
                    hashes[rel_path] = file_hash
                    
                    # 保存更新后的哈希文件
                    with open(hash_file, 'w') as f:
                        json.dump({
                            'algorithm': algorithm,
                            'hashes': hashes
                        }, f, indent=4)
                else:
                    # 如果哈希文件不存在，创建一个新的
                    HashVerifier.generate_hash_file(upload_dir)
                
                # 验证文件完整性
                is_valid = HashVerifier.verify_file_hash(dest_path, file_hash)
                
                # 刷新文件列表
                self.refresh_file_list()
                
                # 更新状态栏并显示验证结果
                if is_valid:
                    self.status_var.set(f"File uploaded: {file_name} (Integrity verified)")
                    messagebox.showinfo("Upload Successful", f"File {file_name} uploaded successfully.\nIntegrity verification: PASSED")
                else:
                    self.status_var.set(f"File uploaded: {file_name} (Integrity check failed)")
                    messagebox.showwarning("Upload Warning", f"File {file_name} uploaded, but integrity verification FAILED!")
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
        
        # 确定源文件路径
        if self.role == 'admin' and '/' in file_name:
            # 管理员下载子文件夹中的文件
            folder, name = file_name.split('/', 1)
            src_path = os.path.join(Path(__file__).parent.parent, "upload_file", folder, name)
            src_dir = os.path.join(Path(__file__).parent.parent, "upload_file", folder)
            display_name = name
        elif self.role == 'admin':
            # 管理员下载根目录中的文件
            src_path = os.path.join(Path(__file__).parent.parent, "upload_file", file_name)
            src_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
            display_name = file_name
        else:
            # 普通用户下载自己文件夹中的文件
            src_path = os.path.join(Path(__file__).parent.parent, "upload_file", self.username, file_name)
            src_dir = os.path.join(Path(__file__).parent.parent, "upload_file", self.username)
            display_name = file_name
        
        try:
            # 确保源文件存在
            if not os.path.exists(src_path):
                messagebox.showerror("Error", f"Source file does not exist: {display_name}")
                return
            
            # 获取下载目录
            download_dir = os.path.join(Path(__file__).parent.parent, "download_file")
            
            # 确保下载目录存在
            if not os.path.exists(download_dir):
                os.makedirs(download_dir)
            
            # 设置目标路径
            dest_path = os.path.join(download_dir, display_name)
            
            # 如果文件已存在，添加用户名前缀避免冲突
            if os.path.exists(dest_path):
                base_name, ext = os.path.splitext(display_name)
                dest_path = os.path.join(download_dir, f"{base_name}_{self.username}{ext}")
            
            # 复制文件
            shutil.copy2(src_path, dest_path)
            
            # 计算源文件的哈希值
            src_hash = HashVerifier.calculate_file_hash(src_path)
            
            # 计算下载文件的哈希值
            dest_hash = HashVerifier.calculate_file_hash(dest_path)
            
            # 验证文件完整性
            is_valid = (src_hash == dest_hash)
            
            # 更新状态栏并显示验证结果
            if is_valid:
                self.status_var.set(f"File downloaded: {display_name} (Integrity verified)")
                messagebox.showinfo("Download Successful", 
                                    f"File {display_name} downloaded successfully to:\n{dest_path}\n\nIntegrity verification: PASSED")
            else:
                self.status_var.set(f"File downloaded: {display_name} (Integrity check failed)")
                messagebox.showwarning("Download Warning", 
                                      f"File {display_name} downloaded to:\n{dest_path}\n\nBut integrity verification FAILED!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")
    
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