import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import socket
import json
from pathlib import Path

from utils.crypto_utils import CryptoType

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

class LoginWindow:
    def __init__(self, root, previous_window=None):
        self.root = root
        self.previous_window = previous_window
        self.root.title("Secure File Transfer System - Login")
        self.root.geometry("400x350")
        
        # 服务器配置
        self.server_host = 'localhost'
        self.server_port = 5163
        
        # 创建主框架
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Secure File transmission", font=("Arial", 16)).pack(pady=10)
        
        # 用户名
        ttk.Label(main_frame, text="Name:").pack(anchor="w", pady=(10, 0))
        self.username_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.username_var, width=30).pack(fill="x", pady=(0, 10))
        
        # 密码
        ttk.Label(main_frame, text="Password:").pack(anchor="w", pady=(10, 0))
        self.password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=30).pack(fill="x", pady=(0, 10))
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20, fill="x")
        
        # 登录按钮
        ttk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        
        # 注册按钮
        ttk.Button(button_frame, text="Register", command=self.show_register_window).pack(side=tk.LEFT, padx=5)
        
        # 状态标签
        self.status_var = tk.StringVar()
        ttk.Label(main_frame, textvariable=self.status_var, foreground="red").pack()
    
    def login(self):
        """处理登录逻辑"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            self.status_var.set("Please enter username and password")
            return
    
        try:
            # 创建Socket连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # 发送认证请求
            auth_data = {
                'type': 'auth',
                'username': username,
                'password': password
            }
            client_socket.send(json.dumps(auth_data).encode('utf-8'))
            
            # 接收响应
            response = client_socket.recv(1024).decode('utf-8')
            auth_result = json.loads(response)
            
            if auth_result['success']:
                currentUser = auth_result['user']
                self.status_var.set(f"Login successful! Role: {currentUser['role']}")
                # 打开主窗口
                self.open_main_window(currentUser)
            else:
                self.status_var.set("Invalid username or password!")
                
        except ConnectionRefusedError:
            self.status_var.set("无法连接到服务器")
        except Exception as e:
            self.status_var.set(f"登录错误: {str(e)}")
        finally:
            client_socket.close()

    def open_main_window(self, user):
        """打开主窗口"""
        # 隐藏登录窗口
        self.root.withdraw()
        
        # 创建主窗口
        main_window = tk.Toplevel(self.root)

        # what crypto mode are we using
        mode=CryptoType.ASYMMETRIC
        # 根据角色打开不同的窗口
        if user['role'] == 'admin':
            # 导入AdminWindow类
            from client.admin_window import AdminWindow
            
            # 初始化管理员窗口
            AdminWindow(main_window, user, self, mode)
        else:
            # 导入MainWindow类
            from client.main_window import MainWindow
            
            # 初始化普通用户窗口
            MainWindow(main_window, user, self, mode)
    
    def create_temp_main_window(self, window, username, role):
        """创建临时主窗口"""
        window.title(f"Secure File Transfer System - User: {username}")
        window.geometry("600x400")
        
        # 确保关闭主窗口时也关闭登录窗口
        window.protocol("WM_DELETE_WINDOW", lambda: self.logout(window))
        
        # 简单的欢迎信息
        ttk.Label(
            window, 
            text=f"Welcome {username}!\nYour role is: {role}", 
            font=("Arial", 14)
        ).pack(pady=50)
        
        # 登出按钮
        ttk.Button(
            window, 
            text="Logout", 
            command=lambda: self.logout(window)
        ).pack(pady=20)
    
    def logout(self, window):
        """登出功能"""
        window.destroy()  # 关闭主窗口
        self.root.deiconify()  # 显示登录窗口
        self.username_var.set("")  # 清空用户名
        self.password_var.set("")  # 清空密码
        self.status_var.set("")    # 清空状态信息
    
    def show_register_window(self):
        """显示注册窗口"""
        register_window = tk.Toplevel(self.root)
        register_window.title("Register New User")
        register_window.geometry("600x400")
        
        # 创建注册框架
        register_frame = ttk.Frame(register_window, padding="20")
        register_frame.pack(fill=tk.BOTH, expand=True)
        
        # 用户名
        ttk.Label(register_frame, text="Username:").pack(anchor="w", pady=(10, 0))
        username_var = tk.StringVar()
        ttk.Entry(register_frame, textvariable=username_var, width=30).pack(fill="x", pady=(0, 10))
        
        # 密码
        ttk.Label(register_frame, text="Password:").pack(anchor="w", pady=(10, 0))
        password_var = tk.StringVar()
        ttk.Entry(register_frame, textvariable=password_var, show="*", width=30).pack(fill="x", pady=(0, 10))
        
        # 确认密码
        ttk.Label(register_frame, text="Confirm Password:").pack(anchor="w", pady=(10, 0))
        confirm_password_var = tk.StringVar()
        ttk.Entry(register_frame, textvariable=confirm_password_var, show="*", width=30).pack(fill="x", pady=(0, 10))
        
        # 状态标签
        status_var = tk.StringVar()
        ttk.Label(register_frame, textvariable=status_var, foreground="red").pack(pady=10)
        
        # 注册按钮
        def do_register():
            username = username_var.get()
            password = password_var.get()
            confirm_password = confirm_password_var.get()
            
            if not username or not password or not confirm_password:
                status_var.set("All fields are required")
                return
            
            if password != confirm_password:
                status_var.set("Passwords do not match")
                return
            
            try:
                # 创建Socket连接
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.server_host, self.server_port))
                
                # 发送注册请求
                register_data = {
                    'type': 'register',
                    'username': username,
                    'password': password
                }
                client_socket.send(json.dumps(register_data).encode('utf-8'))
                
                # 接收响应
                response = client_socket.recv(1024).decode('utf-8')
                result = json.loads(response)
                
                if result['success']:
                    messagebox.showinfo("Registration Successful", result['message'])
                    register_window.destroy()
                else:
                    status_var.set(result['message'])
                    
            except ConnectionRefusedError:
                status_var.set("无法连接到服务器")
            except Exception as e:
                status_var.set(f"注册错误: {str(e)}")
            finally:
                client_socket.close()

        # 注册按钮
        ttk.Button(register_frame, text="Register", command=do_register).pack(pady=10)
        
        # 取消按钮
        ttk.Button(register_frame, text="Cancel", command=register_window.destroy).pack()