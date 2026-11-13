import tkinter as t
from tkinter import ttk, messagebox
import subprocess, json, socket, struct, secrets, time, threading, ipaddress, ctypes, sys
import dns_subscription as subscription
CREATE=0x08000000
PROVIDERS=[('Cloudflare','1.1.1.1','1.0.0.1'),('Google','8.8.8.8','8.8.4.4'),('Quad9 安全过滤','9.9.9.9','149.112.112.112'),('OpenDNS','208.67.222.222','208.67.220.220'),('AdGuard 广告过滤','94.140.14.14','94.140.15.15'),('Cloudflare 家庭过滤','1.1.1.3','1.0.0.3'),('阿里 DNS','223.5.5.5','223.6.6.6'),('腾讯 DNSPod','119.29.29.29',''),('百度 DNS','180.76.76.76',''),('114 DNS','114.114.114.114','114.114.115.115'),('Control D','76.76.2.0','76.76.10.0'),('CleanBrowsing 安全过滤','185.228.168.9','185.228.169.9')]
PROVIDERS += [('AdGuard DNS — Default', '94.140.14.14', '94.140.15.15'), ('AdGuard DNS — Family Protection', '94.140.14.15', '94.140.15.16'), ('AdGuard DNS — Non-filtering', '94.140.14.140', '94.140.14.141'), ('360 Secure DNS', '101.226.4.6', '218.30.118.6'), ('360 Secure DNS', '123.125.81.6', '140.207.198.6'), ('Ali DNS', '223.5.5.5', '223.6.6.6'), ('Caliph DNS', '160.19.167.150', ''), ('Cisco OpenDNS — Standard', '208.67.222.222', '208.67.220.220'), ('Cisco OpenDNS — FamilyShield', '208.67.222.123', '208.67.220.123'), ('Cisco OpenDNS — Sandbox', '208.67.222.2', '208.67.220.2'), ('CleanBrowsing — Family Filter', '185.228.168.168', '185.228.169.168'), ('CleanBrowsing — Adult Filter', '185.228.168.10', '185.228.169.11'), ('CleanBrowsing — Security Filter', '185.228.168.9', '185.228.169.9'), ('Cloudflare DNS — Standard', '1.1.1.1', '1.0.0.1'), ('Cloudflare DNS — Malware blocking only', '1.1.1.2', '1.0.0.2'), ('Cloudflare DNS — Malware and adult content blocking', '1.1.1.3', '1.0.0.3'), ('Comodo Secure DNS', '8.26.56.26', '8.20.247.20'), ('ControlD — Non-filtering', '76.76.2.0', '76.76.10.0'), ('ControlD — Block malware', '76.76.2.1', ''), ('ControlD — Block malware + ads', '76.76.2.2', ''), ('ControlD — Block malware + ads + social', '76.76.2.3', ''), ('DNS.SB', '185.222.222.222', '45.11.45.11'), ('DNSPod Public DNS+', '119.29.29.29', ''), ('DNSWatchGO', '54.174.40.213', '52.3.100.184'), ('Dyn DNS', '216.146.35.35', '216.146.36.36'), ('Freenom World', '80.80.80.80', '80.80.81.81'), ('Google DNS', '8.8.8.8', '8.8.4.4'), ('Hurricane Electric Public Recursor', '74.82.42.42', ''), ('Nawala Childprotection DNS', '180.131.144.144', '180.131.145.145'), ('Neustar Recursive DNS — Reliability & Performance 1', '156.154.70.1', '156.154.71.1'), ('Neustar Recursive DNS — Reliability & Performance 2', '156.154.70.5', '156.154.71.5'), ('Neustar Recursive DNS — Threat Protection', '156.154.70.2', '156.154.71.2'), ('Neustar Recursive DNS — Family Secure', '156.154.70.3', '156.154.71.3'), ('Neustar Recursive DNS — Business Secure', '156.154.70.4', '156.154.71.4'), ('Quad9 DNS — Standard', '9.9.9.9', '149.112.112.112'), ('Quad9 DNS — Unsecured', '9.9.9.10', '149.112.112.10'), ('Quad9 DNS — [ECS](https://en.wikipedia.org/wiki/EDNS_Client_Subnet) support', '9.9.9.11', '149.112.112.11'), ('Safe DNS', '195.46.39.39', '195.46.39.40'), ('Safe Surfer', '104.155.237.225', '104.197.28.121'), ('Surfshark DNS', '194.169.169.169', ''), ('Verisign Public DNS', '64.6.64.6', '64.6.65.6'), ('114DNS — Normal', '114.114.114.114', '114.114.115.115'), ('114DNS — Safe', '114.114.114.119', '114.114.115.119'), ('114DNS — Family', '114.114.114.110', '114.114.115.110'), ('ByteDance Public DNS', '180.184.1.1', '180.184.2.2'), ('CIRA Canadian Shield DNS — Private', '149.112.121.10', '149.112.122.10'), ('CIRA Canadian Shield DNS — Protected', '149.112.121.20', '149.112.122.20'), ('CIRA Canadian Shield DNS — Family', '149.112.121.30', '149.112.122.30'), ('Comss.one DNS — Geo-blocking bypass', '83.220.169.155', '212.109.195.93'), ('Comss.one DNS — Geo-blocking bypass with ad filtering', '195.133.25.16', ''), ('CZ.NIC ODVR', '193.17.47.1', '185.43.135.1'), ('DNS for Family', '94.130.180.225', '78.47.64.161'), ('DNS4EU — Protective resolution', '86.54.11.1', '86.54.11.201'), ('DNS4EU — Protective resolution with child protection', '86.54.11.12', '86.54.11.212'), ('DNS4EU — Protective resolution with ad blocking', '86.54.11.13', '86.54.11.213'), ('DNS4EU — Protective resolution with child protection and ad blocking', '86.54.11.11', '86.54.11.211'), ('DNS4EU — Unfiltered resolution', '86.54.11.100', '86.54.11.200'), ('JupitrDNS', '155.248.232.226', ''), ('LibreDNS', '88.198.92.222', ''), ('OneDNS — Pure Edition', '117.50.10.10', '52.80.52.52'), ('OneDNS — Block Edition', '52.80.66.66', '117.50.22.22'), ('OneDNS — Family Edition', '117.50.60.30', '52.80.60.30'), ('OpenNIC DNS', '217.160.70.42', ''), ('Quad101', '101.101.101.101', '101.102.103.104'), ('SkyDNS RU', '193.58.251.251', ''), ('SWITCH DNS', '130.59.31.248', ''), ('UK DNS Privacy Project', '209.250.227.42', '64.176.190.82'), ('Yandex DNS — Basic', '77.88.8.8', '77.88.8.1'), ('Yandex DNS — Safe', '77.88.8.88', '77.88.8.2'), ('Yandex DNS — Family', '77.88.8.3', '77.88.8.7'), ('AhaDNS — Netherlands', '5.2.75.75', ''), ('AhaDNS — Los Angeles', '45.67.219.208', ''), ('ASTRACAT DNS', '85.209.2.112', ''), ('BlackMagicc DNS', '103.70.12.129', ''), ('DNS Forge', '176.9.93.198', '176.9.1.117'), ('DNSGuard', '62.192.153.242', '62.192.153.243'), ('Dremaxx DNS — Non-filtering', '185.44.82.158', '194.28.99.248'), ('Dremaxx DNS — Adult content blocking', '185.44.82.150', '62.3.50.42'), ('OSZX DNS — OSZX DNS', '51.38.83.141', ''), ('OSZX DNS — PumpleX', '51.38.82.198', ''), ('Privacy-First DNS — Singapore DNS Server', '174.138.21.128', ''), ('Privacy-First DNS — Japan DNS Server', '172.104.93.80', ''), ('Seby DNS — DNS Server 1', '45.76.113.31', '')]

# 运营商地址：公开参考资料，可能限制网络或发生变更。
PROVIDERS += [('中国电信 · 北京', '219.141.136.10', '219.141.140.10'), ('中国电信 · 天津', '219.150.32.132', '219.146.0.132'), ('中国电信 · 上海', '202.96.209.133', '116.228.111.118'), ('中国电信 · 重庆', '61.128.192.68', '61.128.128.68'), ('中国电信 · 河北', '222.222.202.202', ''), ('中国电信 · 山西', '59.49.49.49', ''), ('中国电信 · 内蒙古', '219.148.162.31', '222.74.39.50'), ('中国电信 · 辽宁', '219.148.204.66', ''), ('中国电信 · 吉林', '219.149.194.55', ''), ('中国电信 · 黑龙江', '112.100.100.100', '219.147.198.230'), ('中国电信 · 江苏', '218.2.2.2', '218.4.4.4'), ('中国电信 · 浙江', '202.101.172.35', '202.101.172.47'), ('中国电信 · 安徽', '61.132.163.68', '202.102.213.68'), ('中国电信 · 福建', '218.85.152.99', '218.85.157.99'), ('中国电信 · 江西', '202.101.224.69', '202.101.226.68'), ('中国电信 · 山东', '219.146.1.66', '219.147.1.66'), ('中国电信 · 河南', '222.88.88.88', '222.85.85.85'), ('中国电信 · 湖北', '202.103.24.68', '202.103.0.68'), ('中国电信 · 湖南', '59.51.78.211', '59.51.78.210'), ('中国电信 · 广东', '202.96.128.86', '202.96.128.166'), ('中国电信 · 广西', '202.103.225.68', '202.103.224.68'), ('中国电信 · 海南', '202.100.192.68', ''), ('中国电信 · 四川', '61.139.2.69', '218.6.200.139'), ('中国电信 · 贵州', '202.98.192.67', '202.98.198.167'), ('中国电信 · 云南', '222.172.200.68', '61.166.150.123'), ('中国电信 · 陕西', '218.30.19.40', '61.134.1.4'), ('中国电信 · 甘肃', '202.100.64.68', '61.178.0.93'), ('中国电信 · 新疆', '61.128.114.167', ''), ('中国联通 · 北京', '123.123.123.123', '202.106.0.20'), ('中国联通 · 天津', '202.99.104.68', '202.99.96.68'), ('中国联通 · 上海', '210.22.70.3', '210.22.84.3'), ('中国联通 · 重庆', '221.5.203.98', '221.7.92.98'), ('中国联通 · 河北', '202.99.160.68', '202.99.166.4'), ('中国联通 · 山西', '202.99.192.66', '202.99.192.68'), ('中国联通 · 内蒙古', '202.99.224.68', '202.99.224.8'), ('中国联通 · 辽宁', '202.96.69.38', '202.96.64.68'), ('中国联通 · 吉林', '202.98.0.68', '202.98.5.68'), ('中国联通 · 黑龙江', '202.97.224.69', '202.97.224.68'), ('中国联通 · 江苏', '221.6.4.66', '221.6.4.67'), ('中国联通 · 浙江', '221.12.1.227', '221.12.33.227'), ('中国联通 · 安徽', '218.104.78.25', '58.242.2.2'), ('中国联通 · 福建', '218.104.128.106', ''), ('中国联通 · 江西', '218.248.192.12', ''), ('中国联通 · 山东', '202.102.128.68', '202.102.152.3'), ('中国联通 · 河南', '202.102.224.68', '202.102.227.68'), ('中国联通 · 湖北', '218.108.111.122', ''), ('中国联通 · 湖南', '58.20.127.238', ''), ('中国联通 · 广东', '210.21.196.6', '221.5.88.88'), ('中国联通 · 广西', '221.7.128.68', ''), ('中国联通 · 海南', '221.11.132.2', ''), ('中国联通 · 四川', '119.6.6.6', '124.161.87.155'), ('中国联通 · 贵州', '221.13.30.242', ''), ('中国联通 · 云南', '221.3.131.11', ''), ('中国联通 · 西藏', '221.13.65.34', ''), ('中国联通 · 陕西', '221.11.1.67', '221.11.1.68'), ('中国联通 · 甘肃', '221.7.34.11', ''), ('中国联通 · 宁夏', '221.199.12.157', ''), ('中国联通 · 新疆', '221.7.1.20', ''), ('中国移动 · 北京', '211.136.30.66', '211.136.17.107'), ('中国移动 · 天津', '211.137.160.50', '211.137.160.185'), ('中国移动 · 上海', '211.136.112.50', '211.136.150.66'), ('中国移动 · 重庆', '218.201.4.3', '218.201.21.132'), ('中国移动 · 河北', '211.143.60.56', '211.138.13.66'), ('中国移动 · 山西', '211.138.106.2', '211.138.106.3'), ('中国移动 · 内蒙古', '211.138.91.12', '211.138.91.2'), ('中国移动 · 辽宁', '211.137.32.178', '211.140.197.58'), ('中国移动 · 吉林', '211.141.16.99', '211.141.0.99'), ('中国移动 · 黑龙江', '218.203.59.216', '211.137.241.35'), ('中国移动 · 江苏', '221.131.143.69', '112.4.0.55'), ('中国移动 · 浙江', '211.140.13.188', '211.140.188.188'), ('中国移动 · 安徽', '211.138.180.2', '211.138.180.3'), ('中国移动 · 福建', '211.138.151.161', '211.138.156.66'), ('中国移动 · 江西', '211.141.90.68', '211.141.90.69'), ('中国移动 · 山东', '218.201.96.130', '211.137.191.26'), ('中国移动 · 河南', '211.138.24.66', ''), ('中国移动 · 湖北', '211.137.58.202', '211.137.64.163'), ('中国移动 · 湖南', '211.142.210.98', '211.142.210.99'), ('中国移动 · 广东', '211.136.20.203', '211.136.20.204'), ('中国移动 · 广西', '211.138.245.180', '211.136.17.108'), ('中国移动 · 海南', '221.176.88.95', '211.138.164.6'), ('中国移动 · 四川', '211.137.82.4', '211.137.96.205'), ('中国移动 · 贵州', '211.139.5.29', '211.139.5.30'), ('中国移动 · 云南', '211.139.29.68', '211.139.29.69'), ('中国移动 · 西藏', '211.139.73.34', '211.139.73.35'), ('中国移动 · 陕西', '211.137.130.3', '211.137.130.192'), ('中国移动 · 甘肃', '218.203.160.194', '218.203.160.195'), ('中国移动 · 青海', '211.138.75.123', ''), ('中国移动 · 宁夏', '218.203.123.116', ''), ('中国移动 · 新疆', '218.202.152.130', '218.202.152.131')]

# 来源: VindEi public-dns-directory 与 easonjim/dns-server-list；地址为公开资料。
PROVIDERS += [('114DNS · CN · Standard (Unfiltered)', '114.114.114.114', '114.114.115.115'), ('114DNS · CN · Safe (Malware Blocking)', '114.114.114.119', '114.114.115.119'), ('114DNS · CN · Family Protection', '114.114.114.110', '114.114.115.110'), ('AdGuard DNS · GLOBAL · Default (Ad & Malware Blocking)', '94.140.14.14', '94.140.15.15'), ('AdGuard DNS · GLOBAL · Family Protection', '94.140.14.15', '94.140.15.16'), ('AdGuard DNS · GLOBAL · Non-Filtering', '94.140.14.140', '94.140.14.141'), ('Bharti Airtel · IN · Public Recursor', '125.22.47.125', '202.56.230.5'), ('Alibaba Cloud DNS (AliDNS) · CN · Public Anycast Resolver', '223.5.5.5', '223.6.6.6'), ('Andrews & Arnold (A&A) · GB · Privacy Encrypted Recursor', '217.169.20.20', '217.169.20.21'), ('ArvanCloud DNS · IR · Public Anycast', '185.143.232.232', '185.143.233.233'), ('Baidu Public DNS · CN · Public Anycast', '180.76.76.76', ''), ('Begzar · IR · Developer & Gaming Bypass', '185.55.226.26', '185.55.225.25'), ('British Telecom (BT) · GB · Public Recursor', '62.6.40.178', '62.6.40.162'), ('Chunghwa Telecom (HiNet) · TW · Public Recursor', '168.95.1.1', '168.95.192.1'), ('CIRA Canadian Shield · CA · Private (Unfiltered)', '149.112.121.10', '149.112.122.10'), ('CIRA Canadian Shield · CA · Protected (Threat Protection)', '149.112.121.20', '149.112.122.20'), ('CIRA Canadian Shield · CA · Family', '149.112.121.30', '149.112.122.30'), ('CleanBrowsing · GLOBAL · Security Filter', '185.228.168.9', '185.228.169.9'), ('CleanBrowsing · GLOBAL · Adult Filter', '185.228.168.10', '185.228.169.11'), ('CleanBrowsing · GLOBAL · Family Filter', '185.228.168.168', '185.228.169.168'), ('Cloudflare DNS · GLOBAL · Standard (Unfiltered)', '1.1.1.1', '1.0.0.1'), ('Cloudflare DNS · GLOBAL · Malware Blocking', '1.1.1.2', '1.0.0.2'), ('Cloudflare DNS · GLOBAL · Family / Adult Content Blocking', '1.1.1.3', '1.0.0.3'), ('Comodo / Xcitium Secure DNS · GLOBAL · Malware & Phishing Protection', '8.26.56.26', '8.20.247.20'), ('Control D · GLOBAL · Unfiltered', '76.76.2.0', '76.76.10.0'), ('Control D · GLOBAL · Malware Blocking', '76.76.2.1', '76.76.10.1'), ('Control D · GLOBAL · Ad & Tracker Blocking', '76.76.2.2', '76.76.10.2'), ('Control D · GLOBAL · Family Friendly', '76.76.2.3', '76.76.10.3'), ('CZ.NIC ODVR · CZ · Open DNSSEC Validating Resolver', '193.17.47.1', '185.43.135.1'), ('Deutsche Telekom · DE · Public IP Transit Recursor', '194.25.0.60', '194.25.0.68'), ('DNS Forge · DE · Ad & Tracker Blocking Resolver', '176.9.93.198', '176.9.1.117'), ('DNS.SB · GLOBAL · Zero-Log Anycast', '185.222.222.222', '45.11.45.11'), ('DNS4EU · EU · Protective Resolution', '86.54.11.1', '86.54.11.201'), ('DNS4EU · EU · Child Protection', '86.54.11.12', '86.54.11.212'), ('DNS4EU · EU · Unfiltered Resolution', '86.54.11.100', '86.54.11.200'), ('Tencent DNSPod Public DNS · CN · Public Resolver', '119.29.29.29', '1.12.12.12'), ('Electro DNS · IR · Gaming & Sanction Bypass', '78.157.42.100', '78.157.42.101'), ('French Data Network (FDN) · FR · Uncensored Resolver', '80.67.169.12', '80.67.169.40'), ('Freifunk München · DE · Anycast Public Resolver', '5.1.66.255', ''), ('Gcore Public DNS · GLOBAL · Public Anycast Edge', '95.85.95.85', '2.56.220.2'), ('Google Public DNS · GLOBAL · Public Anycast Recursor', '8.8.8.8', '8.8.4.4'), ('Hurricane Electric · GLOBAL · Public Open Recursor', '74.82.42.42', ''), ('KPN · NL · Public Recursor', '195.121.1.34', '195.121.1.66'), ('KT Corporation (Korea Telecom) · KR · KORNET Public Recursor', '168.126.63.1', '168.126.63.2'), ('LG Uplus · KR · Public Recursor', '164.124.101.2', '203.248.252.2'), ('Lightning Wire Labs (IPFire) · DE · Uncensored Recursor', '81.3.27.54', ''), ('Level 3 / Lumen · GLOBAL · Public Recursor', '4.2.2.1', '4.2.2.2'), ('NextDNS · GLOBAL · Unfiltered Anycast', '45.90.28.0', '45.90.30.0'), ('NTT America (Global IP Network) · GLOBAL · GIN Open Recursor', '129.250.35.250', '129.250.35.251'), ('NWPS.fi · FI · Public (Ad & Malware Blocking)', '95.217.11.63', ''), ('NWPS.fi · FI · Kids Protection', '135.181.103.31', ''), ('NWPS.fi · FI · Protective (Malware Only)', '95.217.244.160', ''), ('NWPS.fi · FI · Unfiltered', '95.216.178.84', ''), ('Cisco Umbrella (OpenDNS) · GLOBAL · Standard Protective', '208.67.222.222', '208.67.220.220'), ('Cisco Umbrella (OpenDNS) · GLOBAL · FamilyShield', '208.67.222.123', '208.67.220.123'), ('OpenNIC Project · GLOBAL · Alternative Root Anycast', '134.195.4.2', ''), ('Optus · AU · Public Recursor', '211.29.132.12', '198.142.0.51'), ('Orange France · FR · Public Recursor', '80.10.246.2', '80.10.246.129'), ('OVPN · SE · RAM-Only Public Recursor', '46.227.67.134', '192.165.9.158'), ('Fundació puntCAT (dns.cat) · ES · Uncensored Catalan Resolver', '109.69.8.51', ''), ('Quad9 · GLOBAL · Secured (Malware Blocking + DNSSEC)', '9.9.9.9', '149.112.112.112'), ('Quad9 · GLOBAL · Unsecured (Unfiltered)', '9.9.9.10', '149.112.112.10'), ('Quad9 · GLOBAL · Secured w/ ECS', '9.9.9.11', '149.112.112.11'), ('SafeDNS · GLOBAL · Threat Protection', '195.46.39.39', '195.46.39.40'), ('Shecan · IR · Sanctions Bypass', '178.22.122.100', '185.51.200.2'), ('Shelter DNS · IR · Gaming & Sanction Bypass', '94.103.125.157', '94.103.125.158'), ('Singtel · SG · Public Recursor', '165.21.83.88', '165.21.100.88'), ('SK Broadband · KR · Public Recursor', '219.250.36.130', '210.220.163.82'), ('SkyDNS · RU · Public Threat Filter', '193.58.251.251', ''), ('StarHub · SG · Public Recursor', '203.116.1.78', '203.116.1.94'), ('Swisscom · CH · Public Recursor', '195.186.1.111', '195.186.4.111'), ('Telefónica / Movistar · ES · Public Recursor', '80.58.61.250', '80.58.61.254'), ('Telstra · AU · Public Recursor', '139.130.4.4', '139.130.4.5'), ('TWNIC Quad101 · TW · Quad101 Public Anycast', '101.101.101.101', '101.102.103.104'), ('Vercara UltraDNS Public · GLOBAL · Threat Protection (ex-Verisign)', '64.6.64.6', '64.6.65.6'), ('Vercara UltraDNS Public · GLOBAL · Reliability & Performance (Neustar Legacy)', '156.154.70.1', '156.154.71.1'), ('Virgin Media · GB · Public Recursor', '194.168.4.100', '194.168.8.100'), ('Yandex DNS · RU · Basic (Unfiltered)', '77.88.8.8', '77.88.8.1'), ('Yandex DNS · RU · Safe (Malware Blocking)', '77.88.8.88', '77.88.8.2'), ('Yandex DNS · RU · Family', '77.88.8.7', '77.88.8.3'), ('公共 DNS 服务器 IP 地址 · 114 DNS', '114.114.114.114', '114.114.115.115'), ('公共 DNS 服务器 IP 地址 · 阿里 AliDNS', '223.5.5.5', '223.6.6.6'), ('公共 DNS 服务器 IP 地址 · 百度 BaiduDNS', '180.76.76.76', ''), ('公共 DNS 服务器 IP 地址 · DNSPod DNS+', '119.29.29.29', '182.254.116.116'), ('公共 DNS 服务器 IP 地址 · CNNIC SDNS', '1.2.4.8', '210.2.4.8'), ('公共 DNS 服务器 IP 地址 · oneDNS', '117.50.11.11', '117.50.22.22'), ('公共 DNS 服务器 IP 地址 · DNS派 电信/移动/铁通', '101.226.4.6', '218.30.118.6'), ('公共 DNS 服务器 IP 地址 · DNS派 联通', '123.125.81.6', '140.207.198.6'), ('公共 DNS 服务器 IP 地址 · Google DNS', '8.8.8.8', '8.8.4.4'), ('公共 DNS 服务器 IP 地址 · IBM Quad9', '9.9.9.9', ''), ('公共 DNS 服务器 IP 地址 · OpenDNS', '208.67.222.222', '208.67.220.220'), ('公共 DNS 服务器 IP 地址 · V2EX DNS', '199.91.73.222', '178.79.131.110'), ('全国各地电信 DNS 服务器 IP 地址 · 安徽电信 DNS', '61.132.163.68', '202.102.213.68'), ('全国各地电信 DNS 服务器 IP 地址 · 北京电信 DNS', '219.141.136.10', '219.141.140.10'), ('全国各地电信 DNS 服务器 IP 地址 · 重庆电信 DNS', '61.128.192.68', '61.128.128.68'), ('全国各地电信 DNS 服务器 IP 地址 · 福建电信 DNS', '218.85.152.99', '218.85.157.99'), ('全国各地电信 DNS 服务器 IP 地址 · 甘肃电信 DNS', '202.100.64.68', '61.178.0.93'), ('全国各地电信 DNS 服务器 IP 地址 · 广东电信 DNS', '202.96.128.86', '202.96.128.166'), ('全国各地电信 DNS 服务器 IP 地址 · 广东电信 DNS', '202.96.134.33', '202.96.128.68'), ('全国各地电信 DNS 服务器 IP 地址 · 广西电信 DNS', '202.103.225.68', '202.103.224.68'), ('全国各地电信 DNS 服务器 IP 地址 · 贵州电信 DNS', '202.98.192.67', '202.98.198.167'), ('全国各地电信 DNS 服务器 IP 地址 · 河南电信 DNS', '222.88.88.88', '222.85.85.85'), ('全国各地电信 DNS 服务器 IP 地址 · 黑龙江电信 DNS', '219.147.198.230', '219.147.198.242'), ('全国各地电信 DNS 服务器 IP 地址 · 湖北电信 DNS', '202.103.24.68', '202.103.0.68'), ('全国各地电信 DNS 服务器 IP 地址 · 湖南电信 DNS', '222.246.129.80', '59.51.78.211'), ('全国各地电信 DNS 服务器 IP 地址 · 江苏电信 DNS', '218.2.2.2', '218.4.4.4'), ('全国各地电信 DNS 服务器 IP 地址 · 江苏电信 DNS', '61.147.37.1', '218.2.135.1'), ('全国各地电信 DNS 服务器 IP 地址 · 江西电信 DNS', '202.101.224.69', '202.101.226.68'), ('全国各地电信 DNS 服务器 IP 地址 · 内蒙古电信 DNS', '219.148.162.31', '222.74.39.50'), ('全国各地电信 DNS 服务器 IP 地址 · 山东电信 DNS', '219.146.1.66', '219.147.1.66'), ('全国各地电信 DNS 服务器 IP 地址 · 陕西电信 DNS', '218.30.19.40', '61.134.1.4'), ('全国各地电信 DNS 服务器 IP 地址 · 上海电信 DNS', '202.96.209.133', '116.228.111.118'), ('全国各地电信 DNS 服务器 IP 地址 · 上海电信 DNS', '202.96.209.5', '108.168.255.118'), ('全国各地电信 DNS 服务器 IP 地址 · 四川电信 DNS', '61.139.2.69', '218.6.200.139'), ('全国各地电信 DNS 服务器 IP 地址 · 天津电信 DNS', '219.150.32.132', '219.146.0.132'), ('全国各地电信 DNS 服务器 IP 地址 · 云南电信 DNS', '222.172.200.68', '61.166.150.123'), ('全国各地电信 DNS 服务器 IP 地址 · 浙江电信 DNS', '202.101.172.35', '61.153.177.196'), ('全国各地电信 DNS 服务器 IP 地址 · 浙江电信 DNS', '61.153.81.75', '60.191.244.5'), ('全国各地联通 DNS 服务器 IP 地址 · 北京联通 DNS', '123.123.123.123', '123.123.123.124'), ('全国各地联通 DNS 服务器 IP 地址 · 北京联通 DNS', '202.106.0.20', '202.106.195.68'), ('全国各地联通 DNS 服务器 IP 地址 · 重庆联通 DNS', '221.5.203.98', '221.7.92.98'), ('全国各地联通 DNS 服务器 IP 地址 · 广东联通 DNS', '210.21.196.6', '221.5.88.88'), ('全国各地联通 DNS 服务器 IP 地址 · 河北联通 DNS', '202.99.160.68', '202.99.166.4'), ('全国各地联通 DNS 服务器 IP 地址 · 河南联通 DNS', '202.102.224.68', '202.102.227.68'), ('全国各地联通 DNS 服务器 IP 地址 · 黑龙江联通 DNS', '202.97.224.69', '202.97.224.68'), ('全国各地联通 DNS 服务器 IP 地址 · 吉林联通 DNS', '202.98.0.68', '202.98.5.68'), ('全国各地联通 DNS 服务器 IP 地址 · 江苏联通 DNS', '221.6.4.66', '221.6.4.67'), ('全国各地联通 DNS 服务器 IP 地址 · 内蒙古联通 DNS', '202.99.224.68', '202.99.224.8'), ('全国各地联通 DNS 服务器 IP 地址 · 山东联通 DNS', '202.102.128.68', '202.102.152.3'), ('全国各地联通 DNS 服务器 IP 地址 · 山东联通 DNS', '202.102.134.68', '202.102.154.3'), ('全国各地联通 DNS 服务器 IP 地址 · 山西联通 DNS', '202.99.192.66', '202.99.192.68'), ('全国各地联通 DNS 服务器 IP 地址 · 陕西联通 DNS', '221.11.1.67', '221.11.1.68'), ('全国各地联通 DNS 服务器 IP 地址 · 上海联通 DNS', '210.22.70.3', '210.22.84.3'), ('全国各地联通 DNS 服务器 IP 地址 · 四川联通 DNS', '119.6.6.6', '124.161.87.155'), ('全国各地联通 DNS 服务器 IP 地址 · 天津联通 DNS', '202.99.104.68', '202.99.96.68'), ('全国各地联通 DNS 服务器 IP 地址 · 浙江联通 DNS', '221.12.1.227', '221.12.33.227'), ('全国各地联通 DNS 服务器 IP 地址 · 辽宁联通 DNS', '202.96.69.38', '202.96.64.68'), ('全国各地移动 DNS 服务器 IP 地址 · 江苏移动 DNS', '221.131.143.69', '112.4.0.55'), ('全国各地移动 DNS 服务器 IP 地址 · 安徽移动 DNS', '211.138.180.2', '211.138.180.3'), ('全国各地移动 DNS 服务器 IP 地址 · 山东移动 DNS', '218.201.96.130', '211.137.191.26'), ('全国各地移动 DNS 服务器 IP 地址 · 广东移动 DNS', '221.179.38.7', '120.196.165.7'), ('全国各地移动 DNS 服务器 IP 地址 · 广东移动 DNS', '211.136.192.6', '120.196.165.24')]

# Same ordered IPv4 pair represents the same configuration; keep first label.
_unique=[]; _pairs=set()
for _entry in PROVIDERS:
 _pair=(_entry[1],_entry[2])
 if _pair not in _pairs: _unique.append(_entry); _pairs.add(_pair)
PROVIDERS=_unique

def ps(s):
 p=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',s],capture_output=True,creationflags=CREATE); return p.returncode,p.stdout.decode('gbk',errors='replace'),p.stderr.decode('gbk',errors='replace')
def query(ip):
 times=[]
 for domain in ['www.microsoft.com','www.baidu.com','www.wikipedia.org']:
  ident=secrets.randbelow(65536); q=struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in domain.split('.'))+b'\0\0\x01\0\x01'
  try:
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(1.5); start=time.perf_counter(); s.sendto(q,(ip,53)); data,addr=s.recvfrom(4096); elapsed=(time.perf_counter()-start)*1000
    if addr[0]==ip and len(data)>=12 and struct.unpack('!H',data[:2])[0]==ident and data[2]&0x80 and not data[3]&15 and struct.unpack('!H',data[6:8])[0]>0: times.append(elapsed)
  except OSError: pass
 return (sum(times)/len(times),len(times)) if times else (None,0)
root=t.Tk(); root.title('DNS 切换工具'); root.geometry('900x690'); root.minsize(800,600)
root.configure(bg='#f3f6fb')
style=ttk.Style(root); style.theme_use('clam')
style.configure('Treeview',background='#ffffff',fieldbackground='#ffffff',foreground='#26354a',rowheight=26,borderwidth=0,font=('Microsoft YaHei UI',10))
style.configure('Treeview.Heading',background='#edf2f9',foreground='#52647b',relief='flat',font=('Microsoft YaHei UI',9,'bold'),padding=(10,9))
style.map('Treeview',background=[('selected','#dbeafe')],foreground=[('selected','#173b72')])
style.configure('TButton',font=('Microsoft YaHei UI',10),padding=(10,5),background='#e9eff8',foreground='#33445e',borderwidth=0)
style.map('TButton',background=[('active','#dce7f6'),('disabled','#eef1f5')])
style.configure('Primary.TButton',font=('Microsoft YaHei UI',10,'bold'),padding=(12,5),background='#2563eb',foreground='#ffffff',borderwidth=0)
style.map('Primary.TButton',background=[('active','#1d4ed8'),('disabled','#9bb7ed')],foreground=[('disabled','#f0f4fa')])
style.configure('TEntry',padding=6)
header=t.Frame(root,bg='#f3f6fb'); header.pack(fill='x',padx=16,pady=(10,4))
t.Label(header,text='DNS 切换工具',font=('Microsoft YaHei UI',16,'bold'),fg='#15243a',bg='#f3f6fb').pack(anchor='w')
t.Label(header,text='选择解析服务，测试响应，再应用到指定网卡',font=('Microsoft YaHei UI',10),fg='#73849a',bg='#f3f6fb').pack(anchor='w',pady=(2,0))
info=t.StringVar(value='测速走当前系统路由；运营商 DNS 可能限网，仅供参考。')
t.Label(root,textvariable=info,anchor='w',font=('Microsoft YaHei UI',9),fg='#55708d',bg='#e8f0fc',padx=12,pady=8).pack(fill='x',padx=16,pady=(4,10))
t.Label(root,text='网络适配器',font=('Microsoft YaHei UI',12,'bold'),fg='#20334d',bg='#f3f6fb').pack(anchor='w',padx=16)
t.Label(root,text='支持 Ctrl 多选 · 包含禁用和虚拟网卡',font=('Microsoft YaHei UI',9),fg='#7d8da1',bg='#f3f6fb').pack(anchor='w',padx=16,pady=(1,5))
adapters=t.Listbox(root,selectmode='extended',height=3,exportselection=False,font=('Microsoft YaHei UI',10),bg='#ffffff',fg='#33455d',selectbackground='#dbeafe',selectforeground='#173b72',relief='flat',highlightthickness=1,highlightbackground='#e1e8f1',activestyle='none'); adapters.pack(fill='x',padx=16,ipady=4)
items=[]
def refresh():
 global items
 # PowerShell output is UTF-8 by explicit setting
 try:
  p=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-NetAdapter -IncludeHidden | Where-Object {$_.InterfaceIndex -gt 0} | Select-Object Name,InterfaceIndex,Status,HardwareInterface | ConvertTo-Json -Compress"],capture_output=True,creationflags=CREATE)
  if p.returncode: raise ValueError(p.stderr.decode('utf-8',errors='replace'))
  data=json.loads(p.stdout.decode('utf-8-sig') or '[]'); items=data if isinstance(data,list) else [data]
  adapters.delete(0,'end')
  for a in items: adapters.insert('end',f"{a['Name']}  |  {a['Status']}  |  {'物理' if a['HardwareInterface'] else '虚拟'}  |  索引 {a['InterfaceIndex']}")
  if items: adapters.selection_set(0)
 except Exception as e: messagebox.showerror('读取网卡失败',str(e))
bar=t.Frame(root,bg='#f3f6fb'); bar.pack(fill='x',padx=16,pady=(4,5))
ttk.Button(bar,text='刷新网卡',command=refresh).pack(side='left')
ttk.Button(bar,text='全选网卡',command=lambda: adapters.selection_set(0,'end')).pack(side='left',padx=5)
directoryhead=t.Frame(root,bg='#f3f6fb'); directoryhead.pack(fill='x',padx=16,pady=(0,6))
t.Label(directoryhead,text='DNS 服务目录',font=('Microsoft YaHei UI',12,'bold'),fg='#20334d',bg='#f3f6fb').pack(side='left')
t.Label(directoryhead,text='点击表头排序 · 测速基于当前网络路由',font=('Microsoft YaHei UI',9),fg='#7d8da1',bg='#f3f6fb').pack(side='right')
treeframe=t.Frame(root,bg='#ffffff',highlightthickness=1,highlightbackground='#e1e8f1'); treeframe.pack(fill='both',expand=True,padx=16)
tree=ttk.Treeview(treeframe,columns=('a','b','speed'),show='tree headings',height=13); tree.heading('#0',text='服务商 / 策略'); tree.heading('a',text='首选 IPv4'); tree.heading('b',text='备用 IPv4'); tree.heading('speed',text='平均查询 / 成功次数'); tree.column('#0',width=350,minwidth=200); tree.column('a',width=140,minwidth=110); tree.column('b',width=140,minwidth=110); tree.column('speed',width=220,minwidth=150); tree.pack(side='left',fill='both',expand=True); scroll=ttk.Scrollbar(treeframe,orient='vertical',command=tree.yview); scroll.pack(side='right',fill='y'); tree.configure(yscrollcommand=scroll.set)
for i,(n,a,b) in enumerate(PROVIDERS): tree.insert('', 'end',iid=str(i),text=n,values=(a,b,'未测试'))
results_by_id={}
subscription_ids=set()
subscription_busy=False
sort_state={'column':'original','reverse':False}
searchbar=t.Frame(root,bg='#f3f6fb'); searchbar.pack(fill='x',padx=16,pady=(0,8),before=treeframe)
t.Label(searchbar,text='搜索',font=('Microsoft YaHei UI',10,'bold'),fg='#53677e',bg='#f3f6fb').pack(side='left',padx=(0,10))
searchvar=t.StringVar(); searchentry=ttk.Entry(searchbar,textvariable=searchvar); searchentry.pack(side='left',fill='x',expand=True)
def filter_rows(*args):
 term=searchvar.get().strip().lower()
 ids=[i for i,(name,a,b) in enumerate(PROVIDERS) if name and term in (name+' '+a+' '+b).lower()]
 col=sort_state['column']; rev=sort_state['reverse']
 if col=='name': ids.sort(key=lambda i: PROVIDERS[i][0].casefold(),reverse=rev)
 elif col=='speed':
  valid=[i for i in ids if i in results_by_id and results_by_id[i][0] is not None]
  missing=[i for i in ids if i not in results_by_id or results_by_id[i][0] is None]
  valid.sort(key=lambda i: results_by_id[i][0],reverse=rev); ids=valid+missing
 for i in range(len(PROVIDERS)):
  if tree.exists(str(i)): tree.detach(str(i))
 for i in ids: tree.reattach(str(i),'','end')
def set_sort(col):
 if sort_state['column']==col: sort_state['reverse']=not sort_state['reverse']
 else: sort_state.update(column=col,reverse=False)
 filter_rows()
tree.heading('#0',text='服务商 / 策略 ↕',command=lambda:set_sort('name'))
tree.heading('speed',text='平均查询 / 成功次数 ↕',command=lambda:set_sort('speed'))
searchvar.trace_add('write',filter_rows)
custom=t.Frame(root,bg='#f3f6fb'); custom.pack(fill='x',padx=16,pady=(10,4))
t.Label(custom,text='自定义 DNS    首选',font=('Microsoft YaHei UI',9,'bold'),fg='#53677e',bg='#f3f6fb').pack(side='left'); first=ttk.Entry(custom,width=18); first.pack(side='left'); t.Label(custom,text='备用',font=('Microsoft YaHei UI',9),fg='#53677e',bg='#f3f6fb',padx=8).pack(side='left'); second=ttk.Entry(custom,width=18); second.pack(side='left')
def add():
 try:
  a=str(ipaddress.IPv4Address(first.get().strip())); b=str(ipaddress.IPv4Address(second.get().strip())) if second.get().strip() else ''
  i=len(PROVIDERS); PROVIDERS.append(('自定义',a,b)); tree.insert('', 'end',iid=str(i),text='自定义',values=(a,b,'未测试')); filter_rows()
 except ValueError: messagebox.showerror('地址错误','请输入有效的 IPv4 地址。')
ttk.Button(custom,text='添加',command=add).pack(side='left',padx=5)
def test():
 btn.config(state='disabled'); info.set('正在测速，逐个查询每个服务商的首选地址……')
 def work():
  from concurrent.futures import ThreadPoolExecutor
  snapshot=[(i,v) for i,v in enumerate(PROVIDERS) if v[0]]
  with ThreadPoolExecutor(max_workers=20) as pool:
   results=list(pool.map(lambda item: query(item[1][1]), snapshot))
  for (i,(_,a,b)),(avg,count) in zip(snapshot,results):
   result=f'{avg:.1f} ms  ({count}/3)' if count else '超时或无有效应答 (0/3)'
   root.after(0,lambda i=i,a=a,b=b,result=result,avg=avg,count=count:(results_by_id.update({i:(avg,count)}),tree.item(str(i),values=(a,b,result))))
  root.after(0,lambda:(btn.config(state='normal'),filter_rows(),info.set('测速完成；点击测速列标题排序；结果仅反映当前系统路由和首选地址。')))
 threading.Thread(target=work,daemon=True).start()
def apply(reset=False):
 selected=adapters.curselection(); row=tree.selection()
 if not selected: messagebox.showerror('请选择网卡','请至少选择一个网卡。'); return
 if not reset and not row: messagebox.showerror('请选择 DNS','请先选择一个 DNS。'); return
 if not ctypes.windll.shell32.IsUserAnAdmin(): messagebox.showerror('需要管理员权限','请右键 EXE，选择“以管理员身份运行”。'); return
 indexes=[int(items[i]['InterfaceIndex']) for i in selected]
 ips=[] if reset else [x for x in PROVIDERS[int(row[0])][1:] if x]
 script="$ErrorActionPreference='Stop'; $failed=@(); "
 for idx in indexes:
  val='-ResetServerAddresses' if reset else "-ServerAddresses @("+','.join("'"+x+"'" for x in ips)+")"
  script+=f"try {{ Set-DnsClientServerAddress -InterfaceIndex {idx} {val} -ErrorAction Stop }} catch {{ $failed += '网卡 {idx}: '+$_.Exception.Message }}; "
 script+="if ($failed.Count) { $failed | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }"
 code,out,err=ps(script)
 if code: messagebox.showerror('部分或全部操作失败',err or out)
 else: messagebox.showinfo('完成','已恢复自动 DNS。' if reset else '已设置所选网卡的 IPv4 DNS。')
buttons=t.Frame(root,bg='#f3f6fb'); buttons.pack(fill='x',padx=16,pady=(8,5))
btn=ttk.Button(buttons,text='测速全部 DNS',command=test); btn.pack(side='left')
ttk.Button(buttons,text='应用选中 DNS',command=apply,style='Primary.TButton').pack(side='left',padx=6)
ttk.Button(buttons,text='恢复自动 DNS',command=lambda:apply(True)).pack(side='left')
subscription_status=t.StringVar(value='订阅：尚未更新')
subbar=t.Frame(root,bg='#f3f6fb')
subbar.pack(side='bottom',fill='x',padx=16,pady=(2,3),before=treeframe)
t.Label(subbar,textvariable=subscription_status,font=('Microsoft YaHei UI',9),fg='#73849a',bg='#f3f6fb').pack(side='left')
def install_subscription(rows,stamp):
 global subscription_ids
 if str(btn['state'])=='disabled':
  root.after(1000,lambda:install_subscription(rows,stamp)); return
 for i in subscription_ids:
  if tree.exists(str(i)): tree.delete(str(i))
  PROVIDERS[i]=('', '', ''); results_by_id.pop(i,None)
 subscription_ids=set()
 existing={(a,b) for name,a,b in PROVIDERS if name}; added=0
 for name,a,b in rows:
  if (a,b) in existing: continue
  existing.add((a,b)); added+=1
  i=len(PROVIDERS); PROVIDERS.append((name,a,b)); subscription_ids.add(i)
  tree.insert('', 'end',iid=str(i),text=name,values=(a,b,'未测试'))
 filter_rows()
 subscription_status.set('订阅：'+(subscription.LAST_REPORT or '缓存')+' · '+(time.strftime('%Y-%m-%d %H:%M',time.localtime(stamp)) if stamp else '部分源未更新')+' · 新增 '+str(added)+' 条')
def update_subscription(manual=False):
 global subscription_busy
 if subscription_busy: return
 subscription_busy=True; subscription_status.set('订阅：正在更新…')
 def worker():
  try:
   rows,stamp=subscription.update()
   root.after(0,lambda:finish_update(rows,stamp,None,manual))
  except Exception as exc:
   error=str(exc); root.after(0,lambda:finish_update(None,0,error,manual))
 threading.Thread(target=worker,daemon=True).start()
def finish_update(rows,stamp,error,manual):
 global subscription_busy
 subscription_busy=False
 if error:
  subscription_status.set('订阅更新失败，继续使用缓存 · '+error[:60])
  if manual: messagebox.showerror('订阅更新失败',error)
 else: install_subscription(rows,stamp)
def automatic_subscription():
 rows,stamp=subscription.load()
 if rows and not subscription_ids: install_subscription(rows,stamp)
 if not stamp or time.time()-stamp>=subscription.INTERVAL: update_subscription()
 root.after(3600000,automatic_subscription)
ttk.Button(subbar,text='立即更新订阅',command=lambda:update_subscription(True)).pack(side='right')
footer=t.Label(root,text='仅设置 IPv4 DNS · 恢复自动 DNS 会重置所选网卡的 DNS 配置 · 浏览器与代理可能使用其他解析方式',font=('Microsoft YaHei UI',9),fg='#8291a4',bg='#f3f6fb')
# Allocate the fixed action area first; the directory takes only remaining space.
footer.pack(side='bottom',anchor='w',padx=16,pady=(2,10),before=treeframe)
buttons.pack_forget(); buttons.pack(side='bottom',fill='x',padx=16,pady=(6,4),before=treeframe)
custom.pack_forget(); custom.pack(side='bottom',fill='x',padx=16,pady=(8,3),before=treeframe)
refresh(); root.after(500,automatic_subscription); root.mainloop()


