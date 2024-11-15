# 端口转发器

这是一个使用Python和Paramiko库实现的图形化SSH端口转发工具，支持SOCKS5和HTTP代理。

## 概览

该项目提供了一个简单的用户界面来设置和管理SSH端口转发、SOCKS5代理和HTTP代理。用户可以通过图形界面轻松配置和管理端口转发规则，而无需手动编辑配置文件或使用命令行工具。

## 前置条件

- Python 3.x
- PyQt5
- Paramiko
- cryptography

## 运行

要运行此项目，请确保您已安装所有必需的Python库。您可以使用以下命令安装依赖项：

```bash
pip install PyQt5 paramiko cryptography
```

然后，您可以通过以下命令启动应用程序：

```bash
python port_forwarder.py
```

## 构建

要构建此项目，您需要安装PyInstaller。您可以使用以下命令安装：

```bash
pip install pyinstaller
```

然后，您可以使用以下命令构建应用程序：

```bash
pyinstaller --onefile --windowed port_forwarder.py
```

## 许可证

本项目采用MIT许可证。有关详细信息，请参阅LICENSE文件。

## 其他信息

- 图形用户界面
- 支持SOCKS5和HTTP代理
- 支持配置的保存和加载
- 支持系统托盘图标
- 支持日志记录

请注意，此README文件已删除了原始README中的个人可识别信息(PII)和某些网站的超链接，以确保隐私和安全。
