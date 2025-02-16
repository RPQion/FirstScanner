import requests
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

def logo() :
    print("""
        Version 1.0 
                    by xiaocaibi
    """)

# 基础配置
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
COMMON_PORTS = [80, 443, 8080, 8000, 22, 21, 3306]
COMMON_DIRS = [
    "admin", "login", "wp-admin", "backup", 
    "config.php", ".git", "phpinfo.php"
]

class Scann:
    def __init__(self, target, ports=None, threads=50):
        self.target = target
        self.ports = ports or COMMON_PORTS
        self.threads = threads
        self.results = []

    def port_scan(self, port):
        """TCP端口扫描"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    self._add_result(f"Port {port} is open")
        except Exception as e:
            pass

    def dir_scan(self, url):
        """敏感目录探测"""
        try:
            headers = {"User-Agent": USER_AGENT}
            response = requests.get(url, headers=headers, timeout=3)
            if response.status_code == 200:
                self._add_result(f"Found: {url}")
        except requests.exceptions.RequestException:
            pass

    def _add_result(self, msg):
        """记录扫描结果"""
        print(f"[+] {msg}")
        self.results.append(msg)

    def start_scan(self):
        """多线程扫描"""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 端口扫描
            if "." in self.target:  # 
                executor.map(self.port_scan, self.ports)
            
            # 目录扫描
            if self.target.startswith("http"):
                base_url = self.target if self.target.endswith("/") else self.target + "/"
                for path in COMMON_DIRS:
                    full_url = urljoin(base_url, path)
                    executor.submit(self.dir_scan, full_url)

    def generate_report(self, filename="scan_report.txt"):
        """生成扫描报告"""
        with open(filename, "w") as f:
            f.write(f"Target for {self.target}\n")
            f.write("="*50 + "\n")
            f.write("\n".join(self.results))
        print(f"\n[+] Report saved to {filename}")

if __name__ == "__main__":
    # 参数解析
    parser = argparse.ArgumentParser(description="The First D Scanner")
    parser.add_argument("target", help="IP or URL")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="目标ip端口")
    args = parser.parse_args()

    # 启动扫描
    logo()
    scanner = Scann(args.target, ports=args.ports)
    scanner.start_scan()
    scanner.generate_report()

    print("\nScan completed!")
