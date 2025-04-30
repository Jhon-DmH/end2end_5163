import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import shutil
import json
from pathlib import Path

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

# 导入哈希验证工具
from utils.hash_utils import HashVerifier

class AdminWindow:
    def __init__(self, root, username, login_window):
        self.root = root
        self.username = username
        self.login_window = login_window
        self.current_path = os.path.join(Path(__file__).parent.parent, "upload_file")
        self.base_path = self.current_path  # 基础路径，不允许回到这个路径之上
        
        # 设置窗口标题和大小
        self.root.title(f"文件管理系统 - 管理员: {username}")
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
        self.back_button = ttk.Button(nav_frame, text="返回上一级", command=self.go_back)
        self.back_button.pack(side=tk.RIGHT)
        
        # 创建文件列表框架
        file_list_frame = ttk.LabelFrame(self.main_frame, text="文件和文件夹")
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
        
        # 上传按钮
        self.upload_button = ttk.Button(button_frame, text="上传文件", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)
        
        # 下载按钮
        self.download_button = ttk.Button(button_frame, text="下载文件", command=self.download_file)
        self.download_button.pack(side=tk.LEFT, padx=5)
        
        # 删除按钮
        self.delete_button = ttk.Button(button_frame, text="删除文件", command=self.delete_file)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        
        # 添加检查文件完整性按钮
        self.check_integrity_button = ttk.Button(button_frame, text="检查文件完整性", command=self.check_file_integrity)
        self.check_integrity_button.pack(side=tk.LEFT, padx=5)
        
        # 登出按钮
        self.logout_button = ttk.Button(button_frame, text="登出", command=self.logout)
        self.logout_button.pack(side=tk.RIGHT, padx=5)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set(f"已登录: {username} (管理员)")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 加载文件列表
        self.refresh_file_list()
        
        # 登录时检查文件完整性
        self.check_file_integrity_on_login()
    
    def update_path_display(self):
        """更新路径显示"""
        rel_path = os.path.relpath(self.current_path, self.base_path)
        if rel_path == ".":
            display_path = "/"
        else:
            display_path = "/" + rel_path.replace("\\", "/")
        self.path_var.set(f"当前位置: {display_path}")
    
    def refresh_file_list(self):
        """刷新文件列表"""
        # 清空列表
        self.file_listbox.delete(0, tk.END)
        
        try:
            # 获取当前目录下的所有项目
            items = os.listdir(self.current_path)
            
            # 先添加文件夹
            for item in sorted(items):
                item_path = os.path.join(self.current_path, item)
                if os.path.isdir(item_path):
                    self.file_listbox.insert(tk.END, f"📁 {item}")
            
            # 再添加文件
            for item in sorted(items):
                item_path = os.path.join(self.current_path, item)
                if os.path.isfile(item_path):
                    self.file_listbox.insert(tk.END, f"📄 {item}")
                    
        except Exception as e:
            messagebox.showerror("错误", f"加载文件列表失败: {str(e)}")
    
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
            new_path = os.path.join(self.current_path, folder_name)
            
            if os.path.isdir(new_path):
                self.current_path = new_path
                self.update_path_display()
                self.refresh_file_list()
    
    def go_back(self):
        """返回上一级目录"""
        # 确保不会超出基础路径
        if os.path.normpath(self.current_path) == os.path.normpath(self.base_path):
            messagebox.showinfo("提示", "已经在根目录，无法返回上一级")
            return
            
        self.current_path = os.path.dirname(self.current_path)
        self.update_path_display()
        self.refresh_file_list()
    
    def upload_file(self):
        """上传文件功能"""
        # 打开文件选择对话框
        file_path = filedialog.askopenfilename(
            title="选择要上传的文件",
            filetypes=[("所有文件", "*.*")]
        )
        
        if file_path:
            # 获取文件名
            file_name = os.path.basename(file_path)
            
            try:
                # 复制文件到当前目录
                dest_path = os.path.join(self.current_path, file_name)
                shutil.copy2(file_path, dest_path)
                
                # 计算文件哈希值
                file_hash = HashVerifier.calculate_file_hash(dest_path)
                
                # 获取根目录路径
                upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
                
                # 生成或更新哈希文件 - 修改为始终存储在根目录
                hash_file = os.path.join(upload_dir, "file_hashes.json")
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
                    self.status_var.set(f"文件已上传: {file_name} (完整性已验证)")
                    messagebox.showinfo("上传成功", f"文件 {file_name} 已上传到当前目录\n完整性验证: 通过")
                else:
                    self.status_var.set(f"文件已上传: {file_name} (完整性检查失败)")
                    messagebox.showwarning("上传警告", f"文件 {file_name} 已上传到当前目录，但完整性验证失败！")
            except Exception as e:
                messagebox.showerror("错误", f"上传文件失败: {str(e)}")
    
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
        src_path = os.path.join(self.current_path, file_name)
        
        if os.path.isfile(src_path):
            try:
                # 获取下载目录
                download_dir = os.path.join(Path(__file__).parent.parent, "download_file")
                
                # 确保下载目录存在
                if not os.path.exists(download_dir):
                    os.makedirs(download_dir)
                
                # 设置目标路径
                dest_path = os.path.join(download_dir, file_name)
                
                # 如果文件已存在，添加时间戳避免冲突
                if os.path.exists(dest_path):
                    import time
                    timestamp = time.strftime("%Y%m%d%H%M%S")
                    base_name, ext = os.path.splitext(file_name)
                    dest_path = os.path.join(download_dir, f"{base_name}_{timestamp}{ext}")
                
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
                    self.status_var.set(f"文件已下载: {file_name} (完整性已验证)")
                    messagebox.showinfo("下载成功", 
                                        f"文件 {file_name} 已下载到:\n{dest_path}\n\n完整性验证: 通过")
                else:
                    self.status_var.set(f"文件已下载: {file_name} (完整性检查失败)")
                    messagebox.showwarning("下载警告", 
                                          f"文件 {file_name} 已下载到:\n{dest_path}\n\n但完整性验证失败！")
            except Exception as e:
                messagebox.showerror("错误", f"下载文件失败: {str(e)}")
    
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
            
        item_path = os.path.join(self.current_path, item_name)
        
        # 确认删除
        if is_folder:
            confirm = messagebox.askyesno("确认删除", f"确定要删除文件夹 {item_name} 及其所有内容吗？")
        else:
            confirm = messagebox.askyesno("确认删除", f"确定要删除文件 {item_name} 吗？")
            
        if confirm:
            try:
                if is_folder:
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
                
                # 更新哈希文件
                upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
                hash_file = os.path.join(upload_dir, "file_hashes.json")
                
                if os.path.exists(hash_file):
                    result = messagebox.askyesno("更新哈希文件", "文件已删除，是否更新哈希值文件？")
                    if result:
                        HashVerifier.generate_hash_file(upload_dir, hash_file)
                        messagebox.showinfo("成功", "哈希值文件已更新")
                    
                # 刷新文件列表
                self.refresh_file_list()
                
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


    def check_file_integrity(self):
        """检查文件完整性并提供更新选项"""
        upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
        hash_file = os.path.join(upload_dir, "file_hashes.json")
        
        if not os.path.exists(hash_file):
            result = messagebox.askyesno("哈希文件不存在", "哈希文件不存在，是否创建新的哈希文件？")
            if result:
                HashVerifier.generate_hash_file(upload_dir)
                messagebox.showinfo("成功", "已成功创建哈希文件")
            return
        
        try:
            all_passed, verification_results = HashVerifier.verify_directory(upload_dir, hash_file)
            
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
                HashVerifier.generate_hash_file(upload_dir, hash_file)
                messagebox.showinfo("成功", "哈希值文件已更新")
                
        except Exception as e:
            messagebox.showerror("错误", f"检查文件完整性时出错: {str(e)}")
    
    def check_file_integrity_on_login(self):
        """登录时检查文件完整性"""
        upload_dir = os.path.join(Path(__file__).parent.parent, "upload_file")
        hash_file = os.path.join(upload_dir, "file_hashes.json")
        
        if not os.path.exists(hash_file):
            result = messagebox.askyesno("哈希文件不存在", "哈希文件不存在，是否创建新的哈希文件？")
            if result:
                HashVerifier.generate_hash_file(upload_dir)
                messagebox.showinfo("成功", "已成功创建哈希文件")
            return
        
        try:
            all_passed, verification_results = HashVerifier.verify_directory(upload_dir, hash_file)
            
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
            message = "登录时文件完整性检查发现以下问题:\n\n"
            
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
            
            result = messagebox.askyesno("登录时完整性检查", message)
            if result:
                HashVerifier.generate_hash_file(upload_dir, hash_file)
                messagebox.showinfo("成功", "哈希值文件已更新")
                
        except Exception as e:
            messagebox.showerror("错误", f"登录时检查文件完整性出错: {str(e)}")