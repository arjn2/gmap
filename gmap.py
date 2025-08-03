# gmap_enhanced.py - IP Range Support
import socket
import concurrent.futures
import time
import os
import ctypes
import ipaddress
import random

from packets import create_syn_packet

class AdvancedPortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.target_results = {}  # Store results per target

    def parse_ip_range(self, ip_input):
        """Parse different IP input formats and return list of IPs."""
        targets = []
        
        try:
            # Method 1: CIDR notation (192.168.1.0/24)
            if '/' in ip_input:
                network = ipaddress.IPv4Network(ip_input, strict=False)
                targets = [str(ip) for ip in network.hosts()]
                print(f"[*] CIDR {ip_input} expanded to {len(targets)} hosts")
                
            # Method 2: IP range with dash (192.168.1.1-192.168.1.100)
            elif '-' in ip_input:
                start_ip, end_ip = ip_input.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                
                targets = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
                print(f"[*] Range {start_ip}-{end_ip} expanded to {len(targets)} hosts")
                
            # Method 3: Comma-separated IPs (192.168.1.1,192.168.1.5,192.168.1.10)
            elif ',' in ip_input:
                ip_list = [ip.strip() for ip in ip_input.split(',')]
                for ip in ip_list:
                    try:
                        # Validate each IP
                        ipaddress.IPv4Address(ip)
                        targets.append(ip)
                    except ipaddress.AddressValueError:
                        # Try to resolve as hostname
                        try:
                            resolved_ip = socket.gethostbyname(ip)
                            targets.append(resolved_ip)
                            print(f"[*] Resolved {ip} -> {resolved_ip}")
                        except socket.gaierror:
                            print(f"[!] Could not resolve: {ip}")
                            
            # Method 4: Single IP or hostname
            else:
                try:
                    # Try as IP first
                    ipaddress.IPv4Address(ip_input)
                    targets.append(ip_input)
                except ipaddress.AddressValueError:
                    # Try as hostname
                    try:
                        resolved_ip = socket.gethostbyname(ip_input)
                        targets.append(resolved_ip)
                        print(f"[*] Resolved {ip_input} -> {resolved_ip}")
                    except socket.gaierror:
                        raise ValueError(f"Invalid IP/hostname: {ip_input}")
                        
        except Exception as e:
            raise ValueError(f"Error parsing IP input: {e}")
            
        return targets

    def scan_port(self, target_ip, port, timeout=1):
        """TCP connect scan for a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    service = self.get_service_banner(target_ip, port)
                    return (port, 'open', service)
                return (port, 'closed', None)
        except socket.timeout:
            return (port, 'filtered', None)
        except Exception:
            return (port, 'filtered', None)

    def get_service_banner(self, target_ip, port):
        """Get service banner from open port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target_ip, port))
                
                if port in [80, 8080]:
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                elif port == 21:
                    pass  # FTP banner comes automatically
                elif port == 22:
                    pass  # SSH banner comes automatically
                
                banner = sock.recv(512)
                return banner.decode('utf-8', errors='ignore').strip()[:50]
        except:
            try:
                return socket.getservbyport(port)
            except:
                return "Unknown service"

    def quick_ping(self, target_ip, timeout=1):
        """Quick TCP ping to check if host is up."""
        common_ports = [80, 443, 22, 21, 25, 53]
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((target_ip, port)) == 0:
                        return True
            except:
                continue
        return False

    def scan_single_target(self, target_ip, port_range, ping_first=True):
        """Scan a single target IP."""
        # Reset per-target results
        target_open = []
        target_closed = []
        target_filtered = []
        
        # Optional ping check
        if ping_first:
            if not self.quick_ping(target_ip):
                print(f"[-] {target_ip} appears to be down or filtered")
                return {
                    'ip': target_ip,
                    'status': 'down',
                    'open_ports': [],
                    'scan_time': 0
                }
        
        print(f"[*] Scanning {target_ip}...")
        start_time = time.time()
        
        # Threaded port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port): port 
                for port in range(port_range[0], port_range[1])
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    port, status, banner = result
                    if status == 'open':
                        target_open.append((port, banner))
                        print(f"[+] {target_ip}:{port} open - {banner}")
                    elif status == 'closed':
                        target_closed.append(port)
                    else:
                        target_filtered.append(port)
        
        scan_time = time.time() - start_time
        
        return {
            'ip': target_ip,
            'status': 'up',
            'open_ports': target_open,
            'closed_ports': len(target_closed),
            'filtered_ports': len(target_filtered),
            'scan_time': scan_time
        }

    def scan_targets(self, targets, port_range=(1, 1024), ping_first=True):
        """Scan multiple targets."""
        print(f"\n{'='*60}")
        print(f"SCANNING {len(targets)} TARGETS")
        print(f"{'='*60}")
        
        all_results = []
        total_start = time.time()
        
        for i, target_ip in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Target: {target_ip}")
            result = self.scan_single_target(target_ip, port_range, ping_first)
            all_results.append(result)
            
            # Progress summary
            if result['status'] == 'up' and result['open_ports']:
                print(f"    └─ Found {len(result['open_ports'])} open ports")
            else:
                print(f"    └─ No open ports or host down")
        
        total_time = time.time() - total_start
        return self.generate_multi_target_report(all_results, total_time)

    def generate_multi_target_report(self, results, total_time):
        """Generate report for multiple targets."""
        up_hosts = [r for r in results if r['status'] == 'up']
        down_hosts = [r for r in results if r['status'] == 'down']
        hosts_with_open_ports = [r for r in up_hosts if r['open_ports']]
        
        report = f"\n{'='*70}\n"
        report += f"SCAN SUMMARY - {len(results)} TARGETS\n"
        report += f"{'='*70}\n"
        report += f"Total Scan Time: {total_time:.2f} seconds\n"
        report += f"Hosts Up: {len(up_hosts)}\n"
        report += f"Hosts Down: {len(down_hosts)}\n"
        report += f"Hosts with Open Ports: {len(hosts_with_open_ports)}\n\n"
        
        if hosts_with_open_ports:
            report += f"DETAILED RESULTS:\n"
            report += f"{'-'*70}\n"
            
            for result in hosts_with_open_ports:
                report += f"\nHost: {result['ip']} ({len(result['open_ports'])} open ports)\n"
                report += f"{'PORT':<8} {'SERVICE':<15} {'BANNER'}\n"
                report += f"{'-'*4:<8} {'-'*7:<15} {'-'*6}\n"
                
                for port, banner in sorted(result['open_ports']):
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    banner_short = banner[:40] + "..." if len(banner) > 40 else banner
                    report += f"{port:<8} {service:<15} {banner_short}\n"
        
        return report

def get_target_selection():
    """Interactive target selection menu."""
    print("\n" + "="*50)
    print("TARGET SELECTION")
    print("="*50)
    print("1. Single IP address      (e.g., 192.168.1.1)")
    print("2. Hostname/Domain        (e.g., google.com)")
    print("3. IP Range with dash     (e.g., 192.168.1.1-192.168.1.100)")
    print("4. CIDR notation          (e.g., 192.168.1.0/24)")
    print("5. Multiple IPs/hosts     (e.g., 192.168.1.1,google.com,10.0.0.1)")
    print("6. Local network scan     (auto-detect network)")
    
    choice = input("\nSelect option (1-6): ").strip()
    
    if choice == '1':
        target = input("Enter IP address: ").strip()
    elif choice == '2':
        target = input("Enter hostname/domain: ").strip()
    elif choice == '3':
        start_ip = input("Start IP: ").strip()
        end_ip = input("End IP: ").strip()
        target = f"{start_ip}-{end_ip}"
    elif choice == '4':
        target = input("Enter CIDR (e.g., 192.168.1.0/24): ").strip()
    elif choice == '5':
        target = input("Enter comma-separated targets: ").strip()
    elif choice == '6':
        # Auto-detect local network
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ".".join(local_ip.split(".")[:-1]) + ".0/24"
            print(f"[*] Detected local network: {network}")
            target = network
        except:
            target = "192.168.1.0/24"  # Default
    else:
        target = input("Enter target: ").strip()
    
    return target

def get_port_range():
    """Interactive port range selection."""
    print("\nPORT RANGE SELECTION:")
    print("1. Quick scan (top 100 ports)")
    print("2. Common ports (1-1024)")
    print("3. Extended scan (1-5000)")
    print("4. Full scan (1-65535)")
    print("5. Custom range")
    print("6. Specific ports")
    
    choice = input("Select option (1-6): ").strip()
    
    if choice == '1':
        # Top 100 common ports
        return [21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080]
    elif choice == '2':
        return (1, 1025)
    elif choice == '3':
        return (1, 5001)
    elif choice == '4':
        return (1, 65536)
    elif choice == '5':
        start = int(input("Start port: "))
        end = int(input("End port: "))
        return (start, end + 1)
    elif choice == '6':
        ports_str = input("Enter ports (comma-separated): ")
        return [int(p.strip()) for p in ports_str.split(',')]
    else:
        return (1, 1025)  # Default

def main():
    print("╔" + "═"*60 + "╗")
    print("║" + " gmap - Enhanced Network Scanner with IP Ranges".center(60) + "║")
    print("╚" + "═"*60 + "╝")
    
    scanner = AdvancedPortScanner()
    
    try:
        # Target selection
        target_input = get_target_selection()
        print(f"\n[*] Target input: {target_input}")
        
        # Parse targets
        targets = scanner.parse_ip_range(target_input)
        
        if not targets:
            print("[!] No valid targets found")
            return
        
        if len(targets) > 50:
            response = input(f"[!] {len(targets)} targets detected. Continue? (y/N): ")
            if response.lower() != 'y':
                return
        
        # Port range selection
        port_config = get_port_range()
        
        # Ping option
        ping_first = input("Ping hosts first to check if up? (Y/n): ").lower() != 'n'
        
        print(f"\n[*] Targets: {len(targets)}")
        if isinstance(port_config, tuple):
            print(f"[*] Port range: {port_config[0]}-{port_config[1]-1}")
        else:
            print(f"[*] Specific ports: {port_config}")
        
        # Execute scan
        if isinstance(port_config, list) and not isinstance(port_config, range):
            # Handle specific ports list
            print("[*] Scanning specific ports...")
            all_results = []
            
            for target_ip in targets:
                target_open = []
                print(f"[*] Scanning {target_ip}...")
                
                for port in port_config:
                    result = scanner.scan_port(target_ip, port)
                    if result and result[1] == 'open':
                        target_open.append((result[0], result[2]))
                        print(f"[+] {target_ip}:{port} open")
                
                all_results.append({
                    'ip': target_ip,
                    'status': 'up' if target_open else 'filtered',
                    'open_ports': target_open,
                    'closed_ports': 0,
                    'filtered_ports': 0,
                    'scan_time': 0
                })
            
            report = scanner.generate_multi_target_report(all_results, 0)
            
        else:
            # Handle port range
            report = scanner.scan_targets(targets, port_config, ping_first)
        
        print(report)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
