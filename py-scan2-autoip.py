import socket
import ipaddress
import concurrent.futures
import time
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.start_time = time.time()
        self.discovered_hosts = []

    def get_local_ip(self):
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return socket.gethostbyname(socket.gethostname())

    def scan_port(self, ip, port, timeout=0.5):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return port, service
            return None
        except:
            return None

    def scan_host(self, ip):
        # Common ports including SSH, HTTP, HTTPS, RDP, VNC, FTP
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 5900, 8080]
        open_ports = []
        
        # First quick check if host is alive
        try:
            socket.setdefaulttimeout(1)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
            
            # Scan ports
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(self.scan_port, ip, port): port 
                                for port in common_ports}
                for future in concurrent.futures.as_completed(future_to_port):
                    if future.result():
                        open_ports.append(future.result())
            
            if open_ports:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                return ip, hostname, open_ports
        except:
            pass
        return None

    def scan_network(self):
        local_ip = self.get_local_ip()
        network = ipaddress.IPv4Network(f'{local_ip}/24', strict=False)
        
        print(f"\n=== Network Scanner ===")
        print(f"Scanner IP: {local_ip}")
        print(f"Scanning network: {network}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nScanning in progress...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_ip = {executor.submit(self.scan_host, str(ip)): ip 
                          for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    self.discovered_hosts.append(result)

        self.print_results()

    def print_results(self):
        scan_duration = time.time() - self.start_time
        
        print("\n=== Scan Results ===")
        for ip, hostname, ports in sorted(self.discovered_hosts):
            print(f"\nHost: {ip} ({hostname})")
            print("Open ports:")
            for port, service in sorted(ports):
                print(f"  - Port {port}: {service}")

        print(f"\nScan completed in {scan_duration:.2f} seconds")
        print(f"Found {len(self.discovered_hosts)} active hosts")

def main():
    scanner = NetworkScanner()
    scanner.scan_network()

if __name__ == "__main__":
    main()