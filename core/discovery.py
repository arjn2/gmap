# core/discovery.py - Handles host ping and discovery

import socket
from utils.validation import validate_ip

@validate_ip
def ping_host(ip, timeout=1):
    """Simple TCP ping to check if host is up."""
    common_ports = [80, 443, 22]
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            continue
    return False
