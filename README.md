# DNS Switcher

一个 Windows DNS 切换与测速工具，支持选择多个网卡、搜索和排序 DNS 目录、添加自定义 IPv4 DNS，以及从多个公共目录更新候选地址。

## 下载和使用

从 [Releases](../../releases) 下载 Windows 版 EXE，无需安装 Python。右键以管理员身份运行，选择目标网卡和 DNS，然后点击“应用选中 DNS”。“恢复自动 DNS”会重置所选网卡的 DNS 配置，包括 IPv6 DNS。

## 功能与限制

- 列出物理、虚拟、已断开和禁用的网卡，支持多选和全选。
- 测速对首选 IPv4 服务器发送 3 次 UDP DNS 查询，显示平均查询耗时和成功次数；使用当前系统路由，不按所选网卡分别测试。
- 内置公共和运营商 DNS，部分运营商地址可能仅对本运营商用户开放或已发生变化。
- 订阅 VindEi、AdGuard、Public DNS Servers 三个目录；在应用运行时定期检查（24 小时），并支持手动更新。软件关闭期间不会后台更新。
- 订阅数据仅添加到候选目录，不会自动切换系统 DNS。同一首选/备用地址组合会去重。
- 当前版本应用的是普通 IPv4 DNS。IPv6、浏览器安全 DNS、代理或 VPN 可能使用其他解析路径。公共服务器的策略及可用性由各自运营者决定。
- 实际切换需要管理员权限；恢复自动 DNS 会重置 DNS 设置，请谨慎全选网卡。

## 从源码运行

需要 Windows、Python 3 和 Tkinter：

```powershell
python dns_switch.py
```

构建独立 EXE：

```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --windowed --name DNS-Switcher dns_switch.py
```

## DNS 目录来源

- [VindEi/public-dns-directory](https://github.com/VindEi/public-dns-directory)
- [AdGuard DNS Knowledge Base](https://github.com/AdguardTeam/KnowledgeBaseDNS/blob/master/docs/general/dns-providers.md)
- [denizsnet/public-dns-servers](https://github.com/denizsnet/public-dns-servers)（数据及文档 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)）
- [easonjim/dns-server-list](https://github.com/easonjim/dns-server-list)
- [各省 DNS 地址参考](https://iswok.cn/5006)

DNS 地址和第三方目录的可用性、运营者政策及授权以各来源为准。

