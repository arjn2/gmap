# core/scanner.py - Handles port scanning

import socket
from utils.validation import timeout_handler
from services.banner import get_banner
from services.fingerprint import detect_os_device

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
