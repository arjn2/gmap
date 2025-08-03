# gmap.py (PURE PYTHON - NO EXTERNAL DEPENDENCIES)
import socket
import concurrent.futures
import time
import os
import ctypes
import errno
import struct
import random

from packets import create_syn_packet

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []

    def scan_port(self, target_ip, port, timeout=1):
        """Performs a TCP connect scan on a single port with detailed error handling."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    service = self.get_service_banner(target_ip, port)
                    return (port, 'open', service)
                elif result == errno.ECONNREFUSED or result == 111:
                    return (port, 'closed', None)
                elif result == errno.ETIMEDOUT or result == 110:
                    return (port, 'filtered', None)
                elif result == errno.EHOSTUNREACH or result == 113:
                    return (port, 'filtered', None)
                else:
                    return (port, 'filtered', None)
                    
        except socket.timeout:
            return (port, 'filtered', None)
        except socket.gaierror:
            return (port, 'filtered', None)
        except OSError:
            return (port, 'filtered', None)
        except Exception:
            return (port, 'filtered', None)

    def get_service_banner(self, target_ip, port):
        """Protocol-aware banner grabbing without external commands."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target_ip, port))
                
                # Protocol-specific banner grabbing
                if port in [80, 8080, 8000]:
                    sock.send(b'GET / HTTP/1.0\r\nHost: ' + target_ip.encode() + b'\r\n\r\n')
                elif port == 443:
                    return "HTTPS (SSL/TLS)"
                elif port == 21:
                    pass  # FTP sends banner automatically
                elif port == 22:
                    pass  # SSH sends banner automatically  
                elif port == 25:
                    sock.send(b'EHLO test.com\r\n')
                elif port == 53:
                    return "DNS"
                elif port == 110:
                    pass  # POP3 sends banner
                elif port == 143:
                    pass  # IMAP sends banner
                elif port == 993:
                    return "IMAPS (SSL/TLS)"
                elif port == 995:
                    return "POP3S (SSL/TLS)"
                else:
                    # Try generic HTTP probe
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                
                banner = sock.recv(1024)
                decoded = banner.decode('utf-8', errors='ignore').strip()
                return decoded[:100] if decoded else "Service detected"
                
        except Exception:
            # Get service name from port number
            try:
                return socket.getservbyport(port)
            except:
                return "Unknown service"

    def tcp_ping(self, target_ip, ports=[80, 443, 22, 21, 25], timeout=1):
        """Pure Python host discovery using TCP connects to common ports."""
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:  # Connection successful
                        return True
                    elif result == errno.ECONNREFUSED:  # Port closed but host up
                        return True
            except:
                continue
        return False

    def icmp_ping(self, target_ip, timeout=2):
        """Pure Python ICMP ping implementation using raw sockets."""
        try:
            # Create raw ICMP socket (requires admin privileges)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            
            # Create ICMP echo request packet
            icmp_id = random.randint(1, 65535)
            icmp_seq = 1
            
            # ICMP header: type(8), code(0), checksum(0), id, sequence
            header = struct.pack('!BBHHH', 8, 0, 0, icmp_id, icmp_seq)
            data = b'Python ping test'
            
            # Calculate checksum
            checksum = self._calculate_checksum(header + data)
            header = struct.pack('!BBHHH', 8, 0, checksum, icmp_id, icmp_seq)
            
            packet = header + data
            sock.sendto(packet, (target_ip, 0))
            
            # Wait for reply
            start_time = time.time()
            while True:
                ready = sock.recv(1024)
                current_time = time.time()
                if current_time - start_time > timeout:
                    sock.close()
                    return False
                
                # Parse ICMP reply (skip IP header)
                icmp_header = ready[20:28]
                if len(icmp_header) >= 8:
                    reply_type, reply_code, reply_checksum, reply_id, reply_seq = struct.unpack('!BBHHH', icmp_header)
                    if reply_type == 0 and reply_id == icmp_id:  # Echo reply
                        sock.close()
                        return True
            
            sock.close()
            return False
            
        except PermissionError:
            # Fall back to TCP ping if no raw socket permissions
            return self.tcp_ping(target_ip)
        except Exception:
            return self.tcp_ping(target_ip)

    def _calculate_checksum(self, data):
        """Calculate checksum for ICMP packet."""
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF

    def discover_host(self, target_ip):
        """Pure Python host discovery without external commands."""
        print(f"[*] Checking if {target_ip} is reachable...")
        
        # Try ICMP ping first
        if self.icmp_ping(target_ip):
            print("[+] Host is up (ICMP echo reply received)")
            return True
        
        # Fall back to TCP ping on common ports
        if self.tcp_ping(target_ip):
            print("[+] Host appears to be up (TCP probe successful)")
            return True
            
        print("[-] Host may be down or heavily firewalled")
        return False

    def scan_target(self, target_ip, port_range=(1, 1024)):
        """Scan target with pure Python implementation."""
        print(f"\nStarting TCP connect scan against {target_ip}")
        print(f"Scanning {port_range[1]-port_range[0]} ports [{port_range[0]}-{port_range[1]-1}]")
        
        start_time = time.time()
        
        # Reset results
        self.open_ports.clear()
        self.closed_ports.clear()
        self.filtered_ports.clear()

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port): port 
                for port in range(port_range[0], port_range[1])
            }
            
            completed = 0
            total = len(future_to_port)
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                completed += 1
                
                if completed % 50 == 0 or completed == total:
                    progress = (completed / total) * 100
                    print(f"\rProgress: {progress:.1f}% [{completed}/{total}]", end='', flush=True)
                
                if result:
                    port, status, banner = result
                    if status == 'open':
                        self.open_ports.append((port, banner))
                        print(f"\n[+] {port}/tcp open - {banner}")
                    elif status == 'closed':
                        self.closed_ports.append(port)
                    else:
                        self.filtered_ports.append(port)

        print()
        scan_time = time.time() - start_time
        return self.generate_report(target_ip, scan_time, port_range)

    def generate_report(self, target_ip, scan_time, port_range):
        """Generate comprehensive scan report."""
        total_ports = port_range[1] - port_range[0]
        
        report = f"\n{'='*60}\n"
        report += f"SCAN COMPLETE - {target_ip}\n"
        report += f"{'='*60}\n"
        report += f"Duration: {scan_time:.2f} seconds\n"
        report += f"Ports Scanned: {total_ports}\n"
        report += f"Rate: {total_ports/scan_time:.0f} ports/sec\n\n"
        
        report += f"SUMMARY:\n"
        report += f"{'─'*20}\n"
        report += f"Open:     {len(self.open_ports):4d}\n"
        report += f"Closed:   {len(self.closed_ports):4d}\n"
        report += f"Filtered: {len(self.filtered_ports):4d}\n\n"
        
        if self.open_ports:
            report += f"OPEN PORTS:\n"
            report += f"{'─'*50}\n"
            report += f"{'PORT':<6} {'STATE':<8} {'SERVICE':<12} {'BANNER'}\n"
            
            for port, banner in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                
                banner_short = banner[:40] + "..." if len(banner) > 40 else banner
                report += f"{port:<6} {'open':<8} {service:<12} {banner_short}\n"
        
        return report

def get_source_ip(target_ip):
    """Get source IP that will be used to reach target."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def is_admin():
    """Check for admin privileges without external commands."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def resolve_hostname(target):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve hostname '{target}': {e}")

def main():
    print("╔" + "═"*50 + "╗")
    print("║" + " gmap - Pure Python Network Scanner".center(50) + "║")
    print("╚" + "═"*50 + "╝")
    
    scanner = PortScanner()
    
    try:
        # Get target
        target = input("\nTarget (IP/hostname): ").strip()
        if not target:
            print("[!] No target specified")
            return
            
        # Resolve target
        try:
            target_ip = resolve_hostname(target)
            print(f"[*] Resolved {target} -> {target_ip}")
        except ValueError as e:
            print(f"[!] {e}")
            return
            
        source_ip = get_source_ip(target_ip)
        print(f"[*] Source IP: {source_ip}")
        
        # Check privileges
        if is_admin():
            print("[+] Running with admin privileges (ICMP ping available)")
        else:
            print("[!] Running without admin privileges (TCP ping only)")

        # Host discovery
        host_up = scanner.discover_host(target_ip)
        if not host_up:
            response = input("Host may be down. Continue scan? (y/N): ").lower()
            if response != 'y':
                print("Scan aborted")
                return

        # Port range selection
        print("\nPort Range Options:")
        print("1. Quick scan (top 100 ports)")
        print("2. Common ports (1-1024)")
        print("3. Extended scan (1-5000)")
        print("4. Custom range")
        
        choice = input("Select option (1-4): ").strip()
        
        if choice == '1':
            # Top 100 most common ports
            common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080]
            port_list = common_ports
        elif choice == '2':
            port_range = (1, 1025)
        elif choice == '3':
            port_range = (1, 5001)
        elif choice == '4':
            try:
                start = int(input("Start port: "))
                end = int(input("End port: "))
                if start < 1 or end > 65535 or start >= end:
                    print("[!] Invalid port range")
                    return
                port_range = (start, end + 1)
            except ValueError:
                print("[!] Invalid port numbers")
                return
        else:
            port_range = (1, 1025)  # Default

        # Handle port list vs range
        if choice == '1':
            print(f"\n[*] Scanning {len(common_ports)} common ports")
            # Custom scan for port list
            start_time = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(scanner.scan_port, target_ip, port) for port in port_list]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        port, status, banner = result
                        if status == 'open':
                            scanner.open_ports.append((port, banner))
                            print(f"[+] {port}/tcp open - {banner}")
            
            scan_time = time.time() - start_time
            print(f"\nScan completed in {scan_time:.2f} seconds")
            print(f"Open ports: {len(scanner.open_ports)}")
            
        else:
            # SYN packet demonstration  
            print(f"\n[*] Creating SYN packet example...")
            try:
                syn_packet = create_syn_packet(source_ip, target_ip, 80)
                print(f"[+] SYN packet ready ({len(syn_packet)} bytes)")
            except Exception as e:
                print(f"[-] SYN packet creation failed: {e}")

            # Perform range scan
            report = scanner.scan_target(target_ip, port_range)
            print(report)
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()




# # gmap.py
# import socket
# import concurrent.futures
# import time
# import os
# import ctypes

# # Import the new packet creation function
# from packets import create_syn_packet

# class PortScanner:
#     def __init__(self):
#         self.open_ports = []
#         self.closed_ports = []
#         self.filtered_ports = []

#     def scan_port(self, target_ip, port, timeout=1):
#         """Performs a TCP connect scan on a single port."""
#         try:
#             # Using SOCK_STREAM performs a TCP 3-way handshake (connect scan)
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#                 sock.settimeout(timeout)
#                 result = sock.connect_ex((target_ip, port))
#                 if result == 0:
#                     # Port is open, try to get service banner
#                     service = self.get_service_banner(target_ip, port)
#                     return (port, 'open', service)
#                 # Other error codes can indicate filtered or closed
#                 return (port, 'closed', None)
#         except socket.timeout:
#             return (port, 'filtered', None)
#         except OSError:
#             return (port, 'filtered', None)

#     def get_service_banner(self, target_ip, port):
#         """Connects to an open port and tries to grab a service banner."""
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#                 sock.settimeout(1)
#                 sock.connect((target_ip, port))
#                 # Send a generic probe for HTTP
#                 sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
#                 banner = sock.recv(1024)
#                 return banner.decode('utf-8', errors='ignore').strip()
#         except Exception:
#             return "No banner available"

#     def scan_target(self, target_ip, port_range=(1, 1024)):
#         """Scans a target IP across a given port range using multiple threads."""
#         print(f"\nScanning {target_ip} (Ports {port_range[0]}-{port_range[1]-1})...")
#         start_time = time.time()

#         with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
#             future_to_port = {
#                 executor.submit(self.scan_port, target_ip, port): port 
#                 for port in range(port_range[0], port_range[1])
#             }
            
#             for future in concurrent.futures.as_completed(future_to_port):
#                 result = future.result()
#                 if result:
#                     port, status, banner = result
#                     if status == 'open':
#                         self.open_ports.append((port, banner))
#                     elif status == 'closed':
#                         self.closed_ports.append(port)
#                     else:
#                         self.filtered_ports.append(port)

#         scan_time = time.time() - start_time
#         return self.generate_report(target_ip, scan_time, port_range)

#     def generate_report(self, target_ip, scan_time, port_range):
#         """Generates a summary report of the scan results."""
#         report = f"\n=== Scan Report for {target_ip} ===\n"
#         report += f"Scan Duration: {scan_time:.2f} seconds\n"
#         report += f"Scanned {port_range[1]-port_range[0]} ports.\n\n"
        
#         report += f"Open Ports: {len(self.open_ports)}\n"
#         report += f"Filtered Ports: {len(self.filtered_ports)}\n"
#         report += f"Closed Ports: {len(self.closed_ports)}\n\n"
        
#         if self.open_ports:
#             report += "Detailed Findings (Open Ports):\n"
#             report += "PORT\tSERVICE\t\tBANNER\n"
#             report += "----\t-------\t\t------\n"
#             for port, banner in sorted(self.open_ports):
#                 try:
#                     service = socket.getservbyport(port)
#                 except OSError:
#                     service = "unknown"
#                 report += f"{port}\t{service.ljust(8)}\t{banner}\n"
        
#         return report

# def get_source_ip(target_ip):
#     """Finds the source IP address that will be used to connect to the target."""
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         s.connect((target_ip, 80))
#         ip = s.getsockname()[0]
#         s.close()
#         return ip
#     except Exception:
#         return "127.0.0.1"

# def is_admin():
#     """Checks for administrator/root privileges."""
#     try:
#         return os.getuid() == 0  # Unix-like systems
#     except AttributeError:
#         return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

# def main():
#     if not is_admin():
#         print("Warning: This script provides more accurate results with administrator privileges.")
#         print("A raw socket SYN scan would require running as administrator/root.")

#     scanner = PortScanner()
#     try:
#         target = input("Enter target IP or hostname: ")
#         target_ip = socket.gethostbyname(target)
#         source_ip = get_source_ip(target_ip)
        
#         print(f"[*] Target: {target} ({target_ip})")
#         print(f"[*] Source IP: {source_ip}")

#         # --- Demonstration of the refactored packet creation ---
#         # Note: This packet is created but not sent. The scan below uses a standard
#         # TCP connect scan, not a raw socket SYN scan.
#         print("[*] Creating a sample SYN packet for port 80 (for demonstration only)...")
#         syn_packet = create_syn_packet(src_ip=source_ip, dst_ip=target_ip, dst_port=80)
#         print(f"[*] Sample SYN packet created successfully ({len(syn_packet)} bytes).")
#         # --------------------------------------------------------

#         report = scanner.scan_target(target_ip)
#         print(report)
#     except socket.gaierror:
#         print(f"Error: Could not resolve hostname '{target}'")
#     except KeyboardInterrupt:
#         print("\nScan aborted by user.")
#     except Exception as e:
#         print(f"\nAn unexpected error occurred: {e}")

# if __name__ == "__main__":
#     main()

