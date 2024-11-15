import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QComboBox, 
                            QPushButton, QMessageBox, QGridLayout, QFrame,
                            QSystemTrayIcon, QMenu, QAction)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QIcon, QPixmap, QKeySequence
from PyQt5.QtWidgets import QShortcut
import paramiko
import socket
import time
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import subprocess
import platform
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import threading
import http.server
import select
import struct

class SSHThread(QThread):
    error_signal = pyqtSignal(str)
    info_signal = pyqtSignal(str)
    connection_started = pyqtSignal()
    connection_stopped = pyqtSignal()
    
    def __init__(self, app, local_port, remote_host, remote_port, ssh_user, ssh_password):
        super().__init__()
        self.app = app
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self.max_retries = 3
        self.retry_interval = 5  # 秒
        
    def run(self):
        retry_count = 0
        self.app.logger.info(f"开始连接: {self.remote_host}:{self.remote_port}")
        
        while retry_count < self.max_retries and not self.app.is_forwarding:  # 修改条件
            try:
                self.app.ssh_client = paramiko.SSHClient()
                self.app.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # 记录连接尝试
                self.app.logger.info(f"尝试 SSH 连接 ({retry_count + 1}/{self.max_retries})")
                
                self.app.ssh_client.connect(
                    self.remote_host,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )

                transport = self.app.ssh_client.get_transport()
                transport.set_keepalive(30)
                
                # 记录端口转发尝试
                self.app.logger.info(f"正在设置端口转发: {self.local_port} -> {self.remote_port}")
                
                transport.request_port_forward('', int(self.local_port))
                
                self.app.is_forwarding = True  # 移到这里
                self.connection_started.emit()
                self.info_signal.emit(f"远程端口转发已启动: {self.remote_host}:{self.local_port} -> 172.24.2.131:{self.remote_port}")
                
                # 记录连接成功
                self.app.logger.info("连接成功建立")
                
                # 添加连接历史
                self.app.add_history_entry()
                
                # 保持连接
                while self.app.is_forwarding and transport.is_active():
                    time.sleep(1)
                    
                break  # 如果连接成功，跳出重试循环
                    
            except Exception as e:
                retry_count += 1
                error_msg = f"连接失败 ({retry_count}/{self.max_retries}): {str(e)}"
                self.error_signal.emit(error_msg)
                self.app.logger.error(error_msg)
                
                if retry_count < self.max_retries:
                    time.sleep(self.retry_interval)
                    self.info_signal.emit(f"正在尝试重新连...")
                else:
                    self.error_signal.emit("重试次数已达上限，停止连接")
                    self.app.logger.error("重试次数已达上限，停止连接")
                    break
        
        self.connection_stopped.emit()
        self.app.cleanup(show_message=False)
        self.app.logger.info("连接已关闭")

class Socks5Server(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

class Socks5Handler(StreamRequestHandler):
    def handle(self):
        # SOCKS5 握手
        version = self.connection.recv(1)
        if version != b'\x05':
            return
        
        nmethods = self.connection.recv(1)
        methods = self.connection.recv(ord(nmethods))
        
        # 发送认证方法（无需认证）
        self.connection.send(b'\x05\x00')
        
        # 获取请求详情
        version = self.connection.recv(1)
        if version != b'\x05':
            return
        
        cmd = self.connection.recv(1)
        if cmd != b'\x01':  # 仅支持 CONNECT
            return
            
        _ = self.connection.recv(1)  # RSV
        atyp = self.connection.recv(1)
        
        if atyp == b'\x01':  # IPv4
            addr = socket.inet_ntoa(self.connection.recv(4))
        elif atyp == b'\x03':  # Domain name
            length = ord(self.connection.recv(1))
            addr = self.connection.recv(length).decode()
        else:
            return
            
        port = struct.unpack('!H', self.connection.recv(2))[0]
        
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((addr, port))
            bind_addr = remote.getsockname()
            
            # 发送成功响应
            self.connection.send(b'\x05\x00\x00\x01' + 
                               socket.inet_aton(bind_addr[0]) + 
                               struct.pack('!H', bind_addr[1]))
        except Exception as e:
            self.connection.send(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            return
            
        # 开始转发数据
        self.forward_data(remote)
        
    def forward_data(self, remote):
        while True:
            r, w, e = select.select([self.connection, remote], [], [])
            if self.connection in r:
                data = self.connection.recv(4096)
                if not data:
                    break
                remote.send(data)
            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                self.connection.send(data)
        remote.close()

class HttpProxyHandler(StreamRequestHandler):
    def handle(self):
        request = self.connection.recv(4096)
        first_line = request.split(b'\n')[0].decode()
        
        try:
            method, url, _ = first_line.split()
        except:
            return
            
        if method == 'CONNECT':
            self.handle_connect(url)
        else:
            self.handle_http(method, url, request)
            
    def handle_connect(self, url):
        host, port = url.split(':')
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((host, int(port)))
            self.connection.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.forward_data(remote)
        except:
            self.connection.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            
    def handle_http(self, method, url, request):
        try:
            # 解析URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 80
            
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((host, port))
            remote.send(request)
            
            response = remote.recv(4096)
            self.connection.send(response)
            self.forward_data(remote)
        except:
            self.connection.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            
    def forward_data(self, remote):
        while True:
            r, w, e = select.select([self.connection, remote], [], [])
            if self.connection in r:
                data = self.connection.recv(4096)
                if not data:
                    break
                remote.send(data)
            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                self.connection.send(data)
        remote.close()

class PortForwarderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("端口转发器")
        self.setGeometry(100, 100, 600, 400)
        
        # 设置应用图标
        icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
        self.app_icon = QIcon(icon_path)
        self.setWindowIcon(self.app_icon)  # 设置窗口图标
        
        # 添加系统托盘
        self.create_tray_icon()
        
        # 配置文件���
        self.config_file = os.path.join(os.path.dirname(__file__), 'config.json')
        self.key_file = os.path.join(os.path.dirname(__file__), '.key')
        
        # 初始化变量
        self.ssh_client = None
        self.is_forwarding = False
        self.configs = {}
        self.ssh_thread = None
        self.start_time = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_connection_time)
        
        # 初始化加密
        self.init_encryption_key()
        
        # 加载配置
        self.load_config()
        
        # 初始化日志
        self.setup_logging()
        
        # 创建UI
        self.init_ui()
        
        self.history_file = os.path.join(os.path.dirname(__file__), 'history.json')
        self.connection_history = []
        self.load_history()
        
    def init_ui(self):
        # 创建主窗口部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 配置选择区域
        config_frame = QFrame()
        config_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        config_layout = QHBoxLayout(config_frame)
        
        config_label = QLabel("已保存配置:")
        self.config_combo = QComboBox()
        self.config_combo.addItems(['新建配置'] + list(self.configs.keys()))
        self.config_combo.currentTextChanged.connect(self.on_config_selected)
        
        save_config_btn = QPushButton("保存当前配置")
        save_config_btn.clicked.connect(self.save_current_config)
        delete_config_btn = QPushButton("删除当前配置")
        delete_config_btn.clicked.connect(self.delete_current_config)
        
        config_layout.addWidget(config_label)
        config_layout.addWidget(self.config_combo)
        config_layout.addWidget(save_config_btn)
        config_layout.addWidget(delete_config_btn)
        
        # 输入表单区域
        form_frame = QFrame()
        form_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.form_layout = QGridLayout(form_frame)  # 只创建一次表单布局
        
        # 创建输入框
        self.local_port = QLineEdit()
        self.remote_host = QLineEdit()
        self.remote_port = QLineEdit()
        self.ssh_user = QLineEdit()
        self.ssh_password = QLineEdit()
        self.ssh_password.setEchoMode(QLineEdit.Password)
        self.protocol = QComboBox()
        self.protocol.addItems(["SSH", "SOCKS5", "HTTP"])
        
        # 连接协议切换信号
        self.protocol.currentTextChanged.connect(self.on_protocol_changed)
        
        # 添加协议选择（始终显示）
        self.form_layout.addWidget(QLabel("协议:"), 0, 0)
        self.form_layout.addWidget(self.protocol, 0, 1)
        
        # 添加本地端口（始终显示）
        self.form_layout.addWidget(QLabel("本地端口:"), 1, 0)
        self.form_layout.addWidget(self.local_port, 1, 1)
        
        # 创建 SSH 相关控件的字典
        self.ssh_widgets = {
            'remote_host_label': QLabel("远程主机:"),
            'remote_host': self.remote_host,
            'remote_port_label': QLabel("远程端口:"),
            'remote_port': self.remote_port,
            'ssh_user_label': QLabel("SSH 用户:"),
            'ssh_user': self.ssh_user,
            'ssh_password_label': QLabel("SSH 密码:"),
            'ssh_password': self.ssh_password
        }
        
        # 初始布局
        self.update_form_layout("SSH")
        
        # 按钮区域
        button_frame = QFrame()
        button_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        button_layout = QHBoxLayout(button_frame)
        
        # 创建按钮
        self.start_button = QPushButton("启动")
        self.stop_button = QPushButton("停止")
        clear_button = QPushButton("清空")
        
        # 连接按钮信号
        self.start_button.clicked.connect(self.start_forwarding)
        self.stop_button.clicked.connect(self.stop_forwarding)
        clear_button.clicked.connect(self.clear_fields)
        
        # 添加状态指示标签
        self.status_label = QLabel("未连接")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #666;
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 3px;
                background: #f8f8f8;
            }
        """)
        
        # 修改按钮布局
        button_layout.addWidget(self.status_label)
        button_layout.addStretch()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(clear_button)
        
        # 添加所有区域到主布局
        main_layout.addWidget(config_frame)
        main_layout.addWidget(form_frame)
        main_layout.addWidget(button_frame)
        
        # 设置样式
        self.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                border-radius: 5px;
                padding: 10px;
                margin: 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 5px 15px;
                border: none;
                border-radius: 3px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton[text="停止"] {
                background-color: #f44336;
            }
            QPushButton[text="停止"]:hover {
                background-color: #da190b;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 3px;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 3px;
            }
        """)

        # 添加快捷键
        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self.save_current_config)
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self.start_forwarding)
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(self.stop_forwarding)
        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self.clear_fields)

        # 为控件添加工具提示
        self.local_port.setToolTip("输入本地端口号")
        self.remote_host.setToolTip("输入远程主机地址")
        self.remote_port.setToolTip("输入远程端口号")
        self.ssh_user.setToolTip("输入SSH用户名")
        self.ssh_password.setToolTip("输入SSH密码")
        self.start_button.setToolTip("启动端口转发 (Ctrl+R)")
        self.stop_button.setToolTip("止端口转发 (Ctrl+T)")
        clear_button.setToolTip("清空所有输入 (Ctrl+N)")
        save_config_btn.setToolTip("保存当前配置 (Ctrl+S)")

    def show_error(self, message):
        QMessageBox.critical(self, "错误", message)
        
    def show_info(self, message):
        QMessageBox.information(self, "信息", message)
        
    def show_warning(self, message):
        QMessageBox.warning(self, "警告", message)

    def on_config_selected(self, selected):
        if selected == '新建配置':
            self.clear_fields()
            return
            
        if selected in self.configs:
            config = self.configs[selected]
            self.local_port.setText(config.get('local_port', ''))
            self.remote_host.setText(config.get('remote_host', ''))
            self.remote_port.setText(config.get('remote_port', ''))
            self.ssh_user.setText(config.get('ssh_user', ''))
            self.ssh_password.setText(self.decrypt_password(config.get('ssh_password', '')))
            self.protocol.setCurrentText(config.get('protocol', 'SSH'))

    def clear_fields(self):
        """清空所有输入框"""
        self.local_port.clear()
        if self.protocol.currentText() == "SSH":
            self.remote_host.clear()
            self.remote_port.clear()
            self.ssh_user.clear()
            self.ssh_password.clear()

    def save_current_config(self):
        """保存当前配置"""
        protocol = self.protocol.currentText()
        
        if protocol == "SSH":
            if not self.remote_host.text() or not self.remote_port.text():
                self.show_error("请至少填写远程主机和端口")
                return
        else:
            if not self.local_port.text():
                self.show_error("请填写本地端口")
                return
            
        config = {
            'protocol': protocol,
            'local_port': self.local_port.text(),
        }
        
        # 只有 SSH 模式才保存这些字段
        if protocol == "SSH":
            config.update({
                'remote_host': self.remote_host.text(),
                'remote_port': self.remote_port.text(),
                'ssh_user': self.ssh_user.text(),
                'ssh_password': self.encrypt_password(self.ssh_password.text()),
            })
            config_id = f"{self.remote_host.text()}:{self.remote_port.text()} [{protocol}]"
        else:
            config_id = f"本地端口 {self.local_port.text()} [{protocol}]"
        
        self.configs[config_id] = config
        self.save_all_configs()
        
        # 更新下拉框
        current_index = self.config_combo.findText(config_id)
        if current_index == -1:
            self.config_combo.addItem(config_id)
            self.config_combo.setCurrentText(config_id)
        
        self.show_info("配置已保存")

    def delete_current_config(self):
        selected = self.config_combo.currentText()
        if selected == '新建配置':
            return
            
        reply = QMessageBox.question(self, '确认', 
                                   f"确定要删除配置 {selected} 吗？",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.configs.pop(selected, None)
            self.save_all_configs()
            self.config_combo.removeItem(self.config_combo.currentIndex())
            self.config_combo.setCurrentText('新建配置')
            self.clear_fields()

    def start_forwarding(self):
        if self.is_forwarding:
            self.show_warning("服务已经在运行中")
            return

        if not self.local_port.text():
            self.show_error("请填写本地端口")
            return

        protocol = self.protocol.currentText()
        
        if protocol == "SSH":
            if not all([self.remote_host.text(), self.remote_port.text(), 
                       self.ssh_user.text(), self.ssh_password.text()]):
                self.show_error("请填写所有SSH相关字段")
                return
            
            # SSH 转发代码
            self.ssh_thread = SSHThread(
                self,
                self.local_port.text(),
                self.remote_host.text(),
                self.remote_port.text(),
                self.ssh_user.text(),
                self.ssh_password.text()
            )
            # 连接信号
            self.ssh_thread.error_signal.connect(self.show_error)
            self.ssh_thread.info_signal.connect(self.show_info)
            self.ssh_thread.connection_started.connect(self.on_connection_started)
            self.ssh_thread.connection_stopped.connect(self.on_connection_stopped)
            
            # 启动线程
            self.ssh_thread.start()
            self.logger.info("SSH线程已启动")
            
        elif protocol == "SOCKS5":
            self.start_socks5_server()
        elif protocol == "HTTP":
            self.start_http_proxy()

    def on_connection_started(self):
        """当连接开始时调用"""
        self.start_time = datetime.now()
        self.timer.start(1000)

    def on_connection_stopped(self):
        """当连接停止时调用"""
        self.timer.stop()
        self.start_time = None
        self.status_label.setText("未连接")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #666;
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 3px;
                background: #f8f8f8;
            }
        """)

    def stop_forwarding(self):
        if not self.is_forwarding:
            self.show_warning("没有正在运行的端口转发")
            return
        
        self.cleanup(show_message=True)

    def cleanup(self, show_message=True):
        was_forwarding = self.is_forwarding
        self.is_forwarding = False
        
        if hasattr(self, 'proxy_server'):
            try:
                self.proxy_server.shutdown()
                self.proxy_server.server_close()
            except:
                pass
            self.proxy_server = None
        
        if self.ssh_client:
            try:
                transport = self.ssh_client.get_transport()
                if transport:
                    transport.cancel_port_forward('', int(self.local_port.text()))
            except:
                pass
            try:
                self.ssh_client.close()
            except:
                pass
            self.ssh_client = None
        
        if show_message and was_forwarding:
            self.show_info("服务已停止")

    def init_encryption_key(self):
        """初始化或加载加密密钥"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    self.key = f.read()
            else:
                # 生成新的密钥
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                self.key = base64.urlsafe_b64encode(kdf.derive(b"PortForwarder"))
                # 保存密钥
                with open(self.key_file, 'wb') as f:
                    f.write(self.key)
            
            self.cipher_suite = Fernet(self.key)
        except Exception as e:
            print(f"始化加密密钥失败: {str(e)}")
            # 使用默认密钥
            self.key = Fernet.generate_key()
            self.cipher_suite = Fernet(self.key)

    def encrypt_password(self, password):
        """加密密码"""
        try:
            if not password:
                return ""
            return self.cipher_suite.encrypt(password.encode()).decode()
        except Exception as e:
            print(f"加密失败: {str(e)}")
            return ""

    def decrypt_password(self, encrypted_password):
        """解密密码"""
        try:
            if not encrypted_password:
                return ""
            return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            print(f"解密失败: {str(e)}")
            return ""

    def load_config(self):
        """加载所有配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                    # 确保加载的数据是字典类型
                    if isinstance(loaded_data, dict):
                        self.configs = loaded_data
                    else:
                        self.configs = {}
            else:
                self.configs = {}
        except Exception as e:
            print(f"加载配置文件失败: {str(e)}")
            self.configs = {}

    def save_all_configs(self):
        """保存所有配置到文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.configs, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"保存配置文件失败: {str(e)}")

    def closeEvent(self, event):
        """重写关闭事件"""
        if self.is_forwarding:
            # 创建自定义按钮的消息框
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle('确认')
            msg_box.setText("端口转发正在运行中，您想要：")
            
            # 创建自定义按钮
            minimize_btn = msg_box.addButton("最小化到托盘", QMessageBox.ActionRole)
            quit_btn = msg_box.addButton("退出程序", QMessageBox.ActionRole)
            cancel_btn = msg_box.addButton("取消", QMessageBox.ActionRole)
            
            # 设置默认按钮
            msg_box.setDefaultButton(minimize_btn)
            
            # 显示对话框
            msg_box.exec_()
            
            # 根据点击的按钮执行相应操作
            clicked_button = msg_box.clickedButton()
            if clicked_button == minimize_btn:
                self.hide()
                self.tray_icon.showMessage(
                    "端口转发器",
                    "应用程序已最小化到系统托盘，双击图标可以重新打开窗口。",
                    QSystemTrayIcon.Information,
                    2000
                )
                event.ignore()
            elif clicked_button == quit_btn:
                self.cleanup(show_message=False)
                event.accept()
            else:  # cancel_btn
                event.ignore()
        else:
            # 创建自定义按钮的消息框
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle('确认')
            msg_box.setText("您想要：")
            
            # 创建自定义按钮
            minimize_btn = msg_box.addButton("最小化到托盘", QMessageBox.ActionRole)
            quit_btn = msg_box.addButton("退出程序", QMessageBox.ActionRole)
            cancel_btn = msg_box.addButton("取消", QMessageBox.ActionRole)
            
            # 设置默认按钮
            msg_box.setDefaultButton(minimize_btn)
            
            # 显示对话框
            msg_box.exec_()
            
            # 根据点击的按钮执行相应操作
            clicked_button = msg_box.clickedButton()
            if clicked_button == minimize_btn:
                self.hide()
                self.tray_icon.showMessage(
                    "端口转发器",
                    "应用程序已最小化到系统托盘，双击图标可以重新打开窗口。",
                    QSystemTrayIcon.Information,
                    2000
                )
                event.ignore()
            elif clicked_button == quit_btn:
                event.accept()
            else:  # cancel_btn
                event.ignore()

    def create_tray_icon(self):
        """创建系统托盘图标"""
        self.tray_icon = QSystemTrayIcon(self)
        
        # 创建托盘图标的右键菜单
        self.tray_menu = QMenu()
        
        # 添加菜单项
        show_action = QAction("显示", self)
        quit_action = QAction("退出", self)
        
        show_action.triggered.connect(self.show)
        quit_action.triggered.connect(self.quit_application)
        
        self.tray_menu.addAction(show_action)
        self.tray_menu.addSeparator()
        self.tray_menu.addAction(quit_action)
        
        # 设置自定义托盘图标
        icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            # 如果找不到自定义图标，使用默认图标
            self.tray_icon.setIcon(QApplication.style().standardIcon(QApplication.style().SP_ComputerIcon))
            
        self.tray_icon.setContextMenu(self.tray_menu)
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
        # 显示托盘图标
        self.tray_icon.show()
        
        # 添加提示文字
        self.tray_icon.setToolTip("端口转发器")

    def tray_icon_activated(self, reason):
        """处理托盘图标的点击事件"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()

    def quit_application(self):
        """退出应用程序"""
        if self.is_forwarding:
            reply = QMessageBox.question(self, '确认', 
                                       "端口转发正在运行中，确定要退出吗？",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return
                
        self.cleanup(show_message=False)
        QApplication.quit()

    def changeEvent(self, event):
        """处理窗口状态改变事件"""
        if event.type() == event.WindowStateChange:
            if self.windowState() & Qt.WindowMinimized:
                # 不做任何特殊处理，让窗口正常最小化到任务栏
                event.accept()

    def update_connection_time(self):
        if self.start_time and self.is_forwarding:
            elapsed = datetime.now() - self.start_time
            hours = elapsed.seconds // 3600
            minutes = (elapsed.seconds % 3600) // 60
            seconds = elapsed.seconds % 60
            self.status_label.setText(
                f"已连接 {hours:02d}:{minutes:02d}:{seconds:02d}"
            )
            self.status_label.setStyleSheet("""
                QLabel {
                    color: #4CAF50;
                    padding: 5px;
                    border: 1px solid #4CAF50;
                    border-radius: 3px;
                    background: #f0f8f0;
                }
            """)

    def setup_logging(self):
        """设置日志系统"""
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        log_file = os.path.join(log_dir, 'port_forwarder.log')
        self.logger = logging.getLogger('PortForwarder')
        self.logger.setLevel(logging.INFO)
        
        # 修改处理器，添加编码设置
        handler = RotatingFileHandler(
            log_file, 
            maxBytes=1024*1024,  # 1MB
            backupCount=5,
            encoding='utf-8'  # 添加 UTF-8 编码设置
        )
        
        # 移除 encoding 参数
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # 添加控制台输出
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.connection_history = json.load(f)
        except Exception as e:
            self.logger.error(f"加载史记录失败: {str(e)}")
            
    def save_history(self):
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.connection_history, f, ensure_ascii=False, indent=4)
        except Exception as e:
            self.logger.error(f"保存历史记录失败: {str(e)}")
            
    def add_history_entry(self):
        entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'remote_host': self.remote_host.text(),
            'remote_port': self.remote_port.text(),
            'local_port': self.local_port.text(),
            'user': self.ssh_user.text()
        }
        self.connection_history.insert(0, entry)
        if len(self.connection_history) > 100:  # 限制历史记录数量
            self.connection_history.pop()
        self.save_history()

    def create_diagnostic_menu(self):
        diagnostic_menu = self.menuBar().addMenu("诊断")
        
        ping_action = QAction("Ping 测试", self)
        ping_action.triggered.connect(self.run_ping_test)
        
        tracert_action = QAction("路由跟踪", self)
        tracert_action.triggered.connect(self.run_tracert)
        
        port_test_action = QAction("端口测试", self)
        port_test_action.triggered.connect(self.test_port)
        
        diagnostic_menu.addAction(ping_action)
        diagnostic_menu.addAction(tracert_action)
        diagnostic_menu.addAction(port_test_action)
        
    def run_ping_test(self):
        if not self.remote_host.text():
            self.show_error("请输入远程主机地址")
            return
            
        host = self.remote_host.text()
        cmd = "ping" if platform.system().lower() == "windows" else "ping -c 4"
        self.run_diagnostic_command(f"{cmd} {host}")
        
    def run_tracert(self):
        if not self.remote_host.text():
            self.show_error("请输入远程主机地址")
            return
            
        host = self.remote_host.text()
        cmd = "tracert" if platform.system().lower() == "windows" else "traceroute"
        self.run_diagnostic_command(f"{cmd} {host}")
        
    def test_port(self):
        if not self.remote_host.text() or not self.remote_port.text():
            self.show_error("请输入远程主机地址和端口")
            return
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.remote_host.text(), int(self.remote_port.text())))
            if result == 0:
                self.show_info("端口开放")
            else:
                self.show_warning("端口未开放")
        except Exception as e:
            self.show_error(f"测试失败: {str(e)}")
        finally:
            sock.close()

    def start_socks5_server(self):
        try:
            server = Socks5Server(('', int(self.local_port.text())), Socks5Handler)
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.proxy_server = server
            self.is_forwarding = True
            self.show_info("SOCKS5 代理服务器已启动")
        except Exception as e:
            self.show_error(f"启动 SOCKS5 代理失败: {str(e)}")

    def start_http_proxy(self):
        try:
            server = TCPServer(('', int(self.local_port.text())), HttpProxyHandler)
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.proxy_server = server
            self.is_forwarding = True
            self.show_info("HTTP 代理服务器已启动")
        except Exception as e:
            self.show_error(f"启动 HTTP 代理失败: {str(e)}")

    def on_protocol_changed(self, protocol):
        """处理协议切换"""
        self.update_form_layout(protocol)
        self.clear_fields()  # 清空所有字段
        
        # 设置默认端口
        if protocol == "HTTP":
            self.local_port.setText("8080")
        elif protocol == "SOCKS5":
            self.local_port.setText("1080")
        
        # 更新工具提示
        if protocol == "SSH":
            self.local_port.setToolTip("SSH本地监听端口")
        elif protocol == "SOCKS5":
            self.local_port.setToolTip("SOCKS5代理监听端口（默认1080）")
        elif protocol == "HTTP":
            self.local_port.setToolTip("HTTP代理监听端口（默认8080）")

    def update_form_layout(self, protocol):
        """更新表单布局"""
        # 隐藏所有 SSH 相关控件
        for widget in self.ssh_widgets.values():
            widget.hide()
        
        # 根据协议显示相应控件
        if protocol == "SSH":
            # 显示所有 SSH 相关控件
            row = 2  # 从第三行开始（前两行是协议和本地端口）
            for label_widget, input_widget in [
                (self.ssh_widgets['remote_host_label'], self.ssh_widgets['remote_host']),
                (self.ssh_widgets['remote_port_label'], self.ssh_widgets['remote_port']),
                (self.ssh_widgets['ssh_user_label'], self.ssh_widgets['ssh_user']),
                (self.ssh_widgets['ssh_password_label'], self.ssh_widgets['ssh_password'])
            ]:
                self.form_layout.addWidget(label_widget, row, 0)
                self.form_layout.addWidget(input_widget, row, 1)
                label_widget.show()
                input_widget.show()
                row += 1
        else:
            # 对于 SOCKS5 和 HTTP，只显示本地端口
            pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PortForwarderApp()
    window.show()
    sys.exit(app.exec_()) 