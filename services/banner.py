# services/banner.py - Service banner grabbing

import socket

def get_banner(ip, port, timeout=1):
    """Grab service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else 'No banner'
    except Exception:
        return 'No banner'
