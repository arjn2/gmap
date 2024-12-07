import socket
import ipaddress
import concurrent.futures
import platform
import subprocess

def get_valid_ip():
    interfaces = socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET)
    for addr in interfaces:
        ip = addr[4][0]
        if not ip.startswith('169.254'):  # Skip link-local addresses
            return ip
    return None

def port_scan(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = "unknown"
            try:
                service = socket.getservbyport(port)
            except:
                pass
            return (port, service)
        sock.close()
    except:
        pass
    return None

def scan_target(target_ip):
    # Common service ports including SSH and VNC
    ports = [22, 5900, 5901, 5902, 80, 443, 3389]
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(port_scan, target_ip, port): port 
                         for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return open_ports if open_ports else None

def main():
    ip = get_valid_ip()
    if not ip:
        print("Error: No valid network connection found")
        print("Please check your network connection and ensure DHCP is working")
        return

    print(f"\nScanning from IP: {ip}")
    network = ipaddress.IPv4Network(f'{ip}/24', strict=False)
    
    for host in network.hosts():
        try:
            if platform.system().lower() == 'windows':
                ping_param = '-n'
            else:
                ping_param = '-c'
            
            subprocess.check_output(['ping', ping_param, '1', str(host)], 
                                 stderr=subprocess.DEVNULL)
            
            ports = scan_target(str(host))
            if ports:
                print(f"\nHost found: {host}")
                print("Open ports:")
                for port, service in ports:
                    print(f"  Port {port}: {service}")
        except:
            continue

if __name__ == "__main__":
    main()