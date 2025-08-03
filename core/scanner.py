# core/scanner.py - Handles port scanning

import socket
from utils.validation import timeout_handler
from services.banner import get_banner
from services.fingerprint import detect_os_device
import concurrent.futures


class Scanner:
    def __init__(self, targets, ports):
        self.targets = targets
        self.ports = ports
        self.results = {}

    @timeout_handler(2)  # 2-second timeout per port
    def scan_port(self, ip, port):
        """Scan single port and detect service/OS."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex((ip, port)) == 0:
                    banner = get_banner(ip, port)
                    service = self.get_service_name(port, banner)
                    os_device = detect_os_device(banner)
                    return {
                        'port': port,
                        'status': 'open',
                        'service': service,
                        'os_device': os_device
                    }
                return {'port': port, 'status': 'closed'}
        except Exception:
            return {'port': port, 'status': 'filtered'}

    def get_service_name(self, port, banner):
        """Simple service name resolution."""
        try:
            return socket.getservbyport(port)
        except OSError:
            return 'unknown' if not banner else banner.split()[0]


    # select packet
   # Enhanced select_scan_type method
    def select_scan_type(self):
        """Allow user to select packet type"""
        print("\nScan Type Selection:")
        print("1. TCP Connect (default)")
        print("2. TCP SYN (stealth)")  
        print("3. TCP FIN")
        print("4. UDP scan")
        choice = input("Select scan type (1-4): ").strip()
        
        scan_types = {
            '1': 'tcp_connect',
            '2': 'tcp_syn', 
            '3': 'tcp_fin',
            '4': 'udp'
        }
        return scan_types.get(choice, 'tcp_connect')



    # Need to add in core/scanner.py
    def scan_target_parallel_ports(self, ip, ports):
        """Parallel port scanning per target"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port 
                              for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
        return results



