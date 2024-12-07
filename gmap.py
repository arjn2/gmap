import socket
import ipaddress
import concurrent.futures
import struct
import time
import os
import ctypes


class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []

    def create_syn_packet(self, dst_port, src_port=12345):
        # Create TCP SYN packet headers
        ip_header = struct.pack('!BBHHHBBH4s4s',
            69,         # Version and IHL
            0,          # Type of Service
            40,         # Total Length
            54321,      # ID
            0,          # Flags and Fragment Offset
            64,         # TTL
            6,          # Protocol (TCP)
            0,          # Checksum (initially 0)
            socket.inet_aton('0.0.0.0'),  # Source Address
            socket.inet_aton('0.0.0.0')   # Destination Address
        )
        return ip_header

    def scan_port(self, target_ip, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    service = self.get_service_banner(sock, port)
                    return (port, 'open', service)
                elif result == 111:  # Connection refused
                    return (port, 'closed', None)
                else:
                    return (port, 'filtered', None)
        except socket.timeout:
            return (port, 'filtered', None)
        except:
            return None

    def get_service_banner(self, sock, port):
        try:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return "No banner available"

    def scan_target(self, target_ip, port_range=(1, 1024)):
        print(f"\nScanning {target_ip}")
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
        return self.generate_report(target_ip, scan_time)

    def generate_report(self, target_ip, scan_time):
        report = f"""
=== Scan Report for {target_ip} ===
Scan Duration: {scan_time:.2f} seconds

Open Ports: {len(self.open_ports)}
Filtered Ports: {len(self.filtered_ports)}
Closed Ports: {len(self.closed_ports)}

Detailed Findings:
"""
        for port, banner in sorted(self.open_ports):
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            report += f"Port {port} ({service}): {banner}\n"
        
        return report

def is_admin():
    try:
        # Check for Unix-like systems
        return os.getuid() == 0
    except AttributeError:
        # Check for Windows systems
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def main():
    if not is_admin():
        print("This script requires administrator privileges")
        print("Please run as administrator/root")
        return

    scanner = PortScanner()
    target = input("Enter target IP: ")
    try:
        report = scanner.scan_target(target)
        print(report)
    except Exception as e:
        print(f"Scan failed: {str(e)}")

if __name__ == "__main__":
    main()