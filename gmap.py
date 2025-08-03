# gmap.py
import socket
import concurrent.futures
import time
import os
import ctypes

# Import the new packet creation function
from packets import create_syn_packet

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []

    def scan_port(self, target_ip, port, timeout=1):
        """Performs a TCP connect scan on a single port."""
        try:
            # Using SOCK_STREAM performs a TCP 3-way handshake (connect scan)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    # Port is open, try to get service banner
                    service = self.get_service_banner(target_ip, port)
                    return (port, 'open', service)
                # Other error codes can indicate filtered or closed
                return (port, 'closed', None)
        except socket.timeout:
            return (port, 'filtered', None)
        except OSError:
            return (port, 'filtered', None)

    def get_service_banner(self, target_ip, port):
        """Connects to an open port and tries to grab a service banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((target_ip, port))
                # Send a generic probe for HTTP
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024)
                return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return "No banner available"

    def scan_target(self, target_ip, port_range=(1, 1024)):
        """Scans a target IP across a given port range using multiple threads."""
        print(f"\nScanning {target_ip} (Ports {port_range[0]}-{port_range[1]-1})...")
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port): port 
                for port in range(port_range[0], port_range[1])
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    port, status, banner = result
                    if status == 'open':
                        self.open_ports.append((port, banner))
                    elif status == 'closed':
                        self.closed_ports.append(port)
                    else:
                        self.filtered_ports.append(port)

        scan_time = time.time() - start_time
        return self.generate_report(target_ip, scan_time, port_range)

    def generate_report(self, target_ip, scan_time, port_range):
        """Generates a summary report of the scan results."""
        report = f"\n=== Scan Report for {target_ip} ===\n"
        report += f"Scan Duration: {scan_time:.2f} seconds\n"
        report += f"Scanned {port_range[1]-port_range[0]} ports.\n\n"
        
        report += f"Open Ports: {len(self.open_ports)}\n"
        report += f"Filtered Ports: {len(self.filtered_ports)}\n"
        report += f"Closed Ports: {len(self.closed_ports)}\n\n"
        
        if self.open_ports:
            report += "Detailed Findings (Open Ports):\n"
            report += "PORT\tSERVICE\t\tBANNER\n"
            report += "----\t-------\t\t------\n"
            for port, banner in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                report += f"{port}\t{service.ljust(8)}\t{banner}\n"
        
        return report

def get_source_ip(target_ip):
    """Finds the source IP address that will be used to connect to the target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def is_admin():
    """Checks for administrator/root privileges."""
    try:
        return os.getuid() == 0  # Unix-like systems
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

def main():
    if not is_admin():
        print("Warning: This script provides more accurate results with administrator privileges.")
        print("A raw socket SYN scan would require running as administrator/root.")

    scanner = PortScanner()
    try:
        target = input("Enter target IP or hostname: ")
        target_ip = socket.gethostbyname(target)
        source_ip = get_source_ip(target_ip)
        
        print(f"[*] Target: {target} ({target_ip})")
        print(f"[*] Source IP: {source_ip}")

        # --- Demonstration of the refactored packet creation ---
        # Note: This packet is created but not sent. The scan below uses a standard
        # TCP connect scan, not a raw socket SYN scan.
        print("[*] Creating a sample SYN packet for port 80 (for demonstration only)...")
        syn_packet = create_syn_packet(src_ip=source_ip, dst_ip=target_ip, dst_port=80)
        print(f"[*] Sample SYN packet created successfully ({len(syn_packet)} bytes).")
        # --------------------------------------------------------

        report = scanner.scan_target(target_ip)
        print(report)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{target}'")
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

