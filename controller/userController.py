import csv
import os
import hashlib
import base64
import uuid
from pathlib import Path
class UserController:
    def __init__(self, user_file='data/users.csv'):
        base_dir = Path(__file__).parent.parent
        self.user_file = os.path.join(base_dir, user_file)
        self._init_user_file()
        self.users = self._load_users()
        self.role_permissions = {
            'admin': {'read': True, 'write': True, 'delete': True},
            'user': {'read': True, 'write': True, 'delete': False}
        }

    def _init_user_file(self):
        """检查用户文件是否存在，如果不存在则创建并添加默认管理员账户"""
        if not os.path.exists(self.user_file):
            # 创建目录
            os.makedirs(os.path.dirname(self.user_file), exist_ok=True)

            # 为管理员生成唯一盐值
            admin_salt = self._generate_salt()

            # 加密管理员密码
            admin_pass = self._hash_password("admin123", "admin", admin_salt)

            # 创建CSV文件并写入管理员账户
            with open(self.user_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['username', 'password', 'salt', 'role'])
                writer.writerow(['admin', admin_pass, admin_salt, 'admin'])

    def _generate_salt(self):
        """生成唯一的盐值"""
        return uuid.uuid4().hex
    def _generate_uid(self):
        """生成唯一的Uid"""
        return uuid.uuid4()

    def _hash_password(self, password, username, salt):
        """使用用户特定的盐值对密码进行哈希处理"""
        salted = password + username + salt
        hashed = hashlib.sha256(salted.encode()).digest()
        return base64.b64encode(hashed).decode('utf-8')

    def _verify_password(self, stored_password, input_password, username, salt):
        """验证密码是否匹配"""
        hashed_input = self._hash_password(input_password, username, salt)
        return stored_password == hashed_input

    def _load_users(self):
        """从CSV文件加载用户数据"""
        users = {}
        try:
            with open(self.user_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    users[row['uid']] = {
                        'username': row['username'],
                        'password': row['password'],
                        'salt': row['salt'],
                        'role': row['role']
                    }
            return users
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}

    def _save_users(self):
        """保存用户数据到CSV文件"""
        try:
            with open(self.user_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['uid','username', 'password', 'salt', 'role'])
                for uid,data in self.users.items():
                    writer.writerow([uid,data['username'], data['password'], data['salt'], data['role']])
            return True
        except Exception as e:
            print(f"Error saving users: {e}")
            return False

    def authenticate(self, username, password):
        """验证用户凭据"""
        for user in self.users.values():
            temp=user['username']
            passResult=self._verify_password(user['password'],password,username,user['salt'])
            if user['username']==username and passResult :
                return user
        return False

    def get_user_role(self, username):
        """获取用户角色"""
        if username in self.users:
            return self.users[username]['role']
        return None

    def register_user(self, username, password):
        """注册新用户（仅限普通用户角色）"""
        # 检查用户名是否已存在
        for user in self.users.values():
            if user['username']==username:
                return False, "Username already exists"

        # 检查密码强度
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"

        # 生成唯一盐值
        salt = self._generate_salt()
        uid = self._generate_uid()
        # 加密密码
        hashed_password = self._hash_password(password, username, salt)

        # 添加新用户（仅限user角色）
        self.users[uid] = {
            'username':username,
            'password': hashed_password,
            'salt': salt,
            'role': 'user'  # 只能注册为普通用户
        }

        # 保存到文件
        if self._save_users():
            return True, "Registration successful"
        else:
            # 如果保存失败，移除新添加的用户
            del self.users[uid]
            return False, "Failed to save user data"

    def check_permission(self, username, permission_type):
        """检查用户是否有特定权限"""
        if username not in self.users:
            return False

        role = self.users[username]['role']
        if role not in self.role_permissions:
            return False

        return self.role_permissions[role].get(permission_type, False)

    def get_user(self,uid,):
        user= self._load_users()
        return user[uid]