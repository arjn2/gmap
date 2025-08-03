# core/scanner.py - Enhanced with device detection

import socket
import concurrent.futures
from utils.validation import timeout_handler
from services.banner import get_banner
from services.device_detector import detect_os_device

class Scanner:
    def __init__(self, targets, ports):
        self.targets = targets
        self.ports = ports
        self.results = {}
        self.scan_type = 'tcp_connect'  # Default

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
        self.scan_type = scan_types.get(choice, 'tcp_connect')
        return self.scan_type

    @timeout_handler(2)
    def scan_port(self, ip, port):
        """Scan single port with enhanced device detection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex((ip, port)) == 0:
                    banner = get_banner(ip, port)
                    service = self.get_service_name(port, banner)
                    
                    # Enhanced device detection with port context
                    device_info = detect_os_device(banner, [port], ip)
                    
                    return {
                        'port': port,
                        'status': 'open',
                        'service': service,
                        'banner': banner[:50] + '...' if len(banner) > 50 else banner,
                        'device_type': device_info['device_type'],
                        'os': device_info['os'],
                        'vendor': device_info['vendor'],
                        'confidence': device_info['confidence']
                    }
                return {'port': port, 'status': 'closed'}
        except Exception:
            return {'port': port, 'status': 'filtered'}

    def get_service_name(self, port, banner):
        """Enhanced service name resolution."""
        try:
            service = socket.getservbyport(port)
            # Add protocol info if available in banner
            if banner:
                if 'HTTP' in banner.upper():
                    service += ' (HTTP)'
                elif 'SSH' in banner.upper():
                    service += ' (SSH)'
                elif 'FTP' in banner.upper():
                    service += ' (FTP)'
            return service
        except OSError:
            return 'unknown' if not banner else banner.split()[0]

    def scan_target_parallel_ports(self, ip, ports):
        """Parallel port scanning per target with device correlation."""
        results = []
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port 
                              for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    if result['status'] == 'open':
                        open_ports.append(result['port'])
        
        # Final device detection with all port context
        if results and open_ports:
            combined_banner = ' '.join([r.get('banner', '') for r in results if r.get('banner')])
            final_device = detect_os_device(combined_banner, open_ports, ip)
            
            # Update all results with final device info
            for result in results:
                if result['status'] == 'open':
                    result.update({
                        'final_device_type': final_device['device_type'],
                        'final_os': final_device['os'],
                        'final_vendor': final_device['vendor']
                    })
        
        return results



# # core/scanner.py - Handles port scanning

# import socket
# from utils.validation import timeout_handler
# from services.banner import get_banner
# from services.fingerprint import detect_os_device
# import concurrent.futures


# class Scanner:
#     def __init__(self, targets, ports):
#         self.targets = targets
#         self.ports = ports
#         self.results = {}

#     @timeout_handler(2)  # 2-second timeout per port
#     def scan_port(self, ip, port):
#         """Scan single port and detect service/OS."""
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#                 if sock.connect_ex((ip, port)) == 0:
#                     banner = get_banner(ip, port)
#                     service = self.get_service_name(port, banner)
#                     os_device = detect_os_device(banner)
#                     return {
#                         'port': port,
#                         'status': 'open',
#                         'service': service,
#                         'os_device': os_device
#                     }
#                 return {'port': port, 'status': 'closed'}
#         except Exception:
#             return {'port': port, 'status': 'filtered'}

#     def get_service_name(self, port, banner):
#         """Simple service name resolution."""
#         try:
#             return socket.getservbyport(port)
#         except OSError:
#             return 'unknown' if not banner else banner.split()[0]


#     # select packet
#    # Enhanced select_scan_type method
#     def select_scan_type(self):
#         """Allow user to select packet type"""
#         print("\nScan Type Selection:")
#         print("1. TCP Connect (default)")
#         print("2. TCP SYN (stealth)")  
#         print("3. TCP FIN")
#         print("4. UDP scan")
#         choice = input("Select scan type (1-4): ").strip()
        
#         scan_types = {
#             '1': 'tcp_connect',
#             '2': 'tcp_syn', 
#             '3': 'tcp_fin',
#             '4': 'udp'
#         }
#         return scan_types.get(choice, 'tcp_connect')



#     # Need to add in core/scanner.py
#     def scan_target_parallel_ports(self, ip, ports):
#         """Parallel port scanning per target"""
#         results = []
#         with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
#             future_to_port = {executor.submit(self.scan_port, ip, port): port 
#                               for port in ports}
#             for future in concurrent.futures.as_completed(future_to_port):
#                 result = future.result()
#                 if result:
#                     results.append(result)
#         return results




