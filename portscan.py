# -*- coding: utf-8 -*-
# 开发团队   ：漫游边界
# 开发人员   ：Akira
# 开发时间   ：2020/4/10  10:27 
# 文件名称   ：threading.PY
# 开发工具   ：PyCharm


import sys
import socket
import requests
import multiprocessing as mp
import dns.resolver
from time import time
from bs4 import BeautifulSoup
from fake_useragent import UserAgent


class Scanner(object):
    def __init__(self, target, start, end):
        self.target = target
        self.start = start
        self.end = end
        self.time = time()
        self.ports = []
        self.result = []
        self.lock = mp.Manager().Lock()
        self.get_ports()

    # 检测目标是IP还是域名
    def ckeck_target(self):
        target = self.target.split('.')[-1]
        try:
            if int(target) >= 0:
                self._start()
        except:
            if not self.check_cdn():
                self._start()
            else:
                print('*' * 50)
                print(f'[-] 目标使用了CDN技术,停止扫描')
                print('*' * 50)

    # 解析目标地址，看有没有多个IP来判断是否使用CDN技术
    def check_cdn(self):
        Resolver = dns.resolver.Resolver()
        Resolver.lifetime = Resolver.timeout = 2.0
        dnsserver = [['114.114.114.114'], ['8.8.8.8'], ['223.6.6.6']]
        try:
            for i in dnsserver:
                Resolver.nameservers = i
                record = Resolver.query(self.target)
                self.result.append(record[0].address)
        except Exception as e:
            pass
        finally:
            return True if len(set(list(self.result))) > 1 else False

    # 读取用户输入的端口范围
    def get_ports(self):
        for i in range(int(self.start), int(self.end)):
            self.ports.append(i)

    # http方式去获取banner
    def get_http_banner(self, url):
        try:
            r = requests.get(url=url, header={'UserAgent':UserAgent().random}, timeout=2, verify=False, allow_redirects=True)
            soup = BeautifulSoup(r.content, 'lxml')
            return soup.title.text.strip('\n').strip()
        except Exception as e:
            pass

    # 利用socket方式去获取banner
    def get_socket_info(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.2)
            s.connect((self.target, port))
            s.send('HELLO\r\n'.encode())
            return s.recv(1024).split('\r\n'.encode())[0].strip('\r\n'.encode())
        except Exception as e:
            print(e)
        finally:
            s.close()

    # 用socket来测试端口有没有开启
    def scan_port(self, port):
        link = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            link.settimeout(0.2)
            return True if link.connect_ex((self.target, port)) == 0 else False
        except Exception as e:
            print(e)
        finally:
            link.close()

    def run(self, port):
        try:
            if self.scan_port(port):
                banner = self.get_http_banner(f'http://{self.target}:{port}')
                self.lock.acquire()
                if banner:
                    print(f'[+] {str(port).rjust(6)} ---- open   {banner[:18]}')
                else:
                    banner = self.get_socket_info(port)
                    if banner:
                        print(f'[+] {str(port).rjust(6)} ---- open   {banner[:18]}')
                    else:
                        print(f'[+] {str(port).rjust(6)} ---- open   ')
                self.lock.release()
        except Exception as e:
            pass

    # 主程序
    def _start(self):
        try:
            print('*' * 50)
            print(f'[-] 正在扫描地址:{socket.gethostbyname(self.target)}')
            print('*' * 50)
            pool = mp.Pool()
            pool.map(self.run, self.ports)
            pool.close()
            pool.join()
            print('*' * 50)
            print(f'[-] 扫描完成耗时: {time()-self.time} 秒.')
            print('*' * 50)
        except Exception as e:
            print(e)
        except KeyboardInterrupt:
            sys.exit(1)


if __name__ == '__main__':
    banner = '''  ____               _    ____                     
 |  _ \  ___   _ __ | |_ / ___|   ___  __ _  _ __  
 | |_) |/ _ \ | '__|| __|\___ \  / __|/ _` || '_ \ 
 |  __/| (_) || |   | |_  ___) || (__| (_| || | | |
 |_|    \___/ |_|    \__||____/  \___|\__,_||_| |_|
                                                   '''
    print(f'usage: author:Akira')
    print(banner)
    # if len(sys.argv) != 4:
    #     print(f'help: python {sys.argv[0]} url port_start port_end')
    #     exit(0)
    # else:
    with open('ip.txt', 'r') as fp:
        for line in fp.readlines():
            scan = Scanner(line.strip(), 1, 10000)
            scan.ckeck_target()
