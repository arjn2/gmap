import subprocess
import platform
import psutil
import re
import time
import threading
import socket
import json
import winreg

class BSSIDTracker:
    def __init__(self):
        self.tracked_processes = {}
        self.suspicious_connections = []

    def get_current_wifi_bssid(self):
        """Get current WiFi BSSID"""
        try:
            output = subprocess.check_output(
                "netsh wlan show interfaces", 
                shell=True, 
                text=True
            )
            match = re.search(r'BSSID\s*:\s*([0-9A-Fa-f:]+)', output)
            return match.group(1) if match else None
        except Exception:
            return None

    def network_connection_monitor(self):
        """Monitor network connections for BSSID-related traffic"""
        
        # Define suspicious domains outside loop
        suspicious_domains = [
            'accuweather.com',
            'vortex.accuweather.com',
            'reveal.mobile',
            'tracking'
        ]
        
        while True:
            try:
                for conn in psutil.net_connections():
                    try:
                        process = psutil.Process(conn.pid)
                        remote_ip = conn.raddr.ip if conn.raddr else None
                        
                        if remote_ip:
                            try:
                                hostname = socket.gethostbyaddr(remote_ip)[0]
                                current_bssid = self.get_current_wifi_bssid()
                                connection_info = {
                                    'process_name': process.name(),
                                    'pid': conn.pid,
                                    'remote_host': hostname,
                                    'remote_ip': remote_ip,
                                    'current_bssid': current_bssid,
                                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                }
                                self.suspicious_connections.append(connection_info)
                                print(f"Suspicious Connection Detected: {json.dumps(connection_info, indent=2)}")

                            except socket.herror:
                                hostname = remote_ip

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    
            except Exception as e:
                print(f"Error monitoring connections: {e}")
            
            time.sleep(1)  # Add delay to prevent high CPU usage

    def start_monitoring(self):
        """Start network connection monitoring"""
        monitor_thread = threading.Thread(
            target=self.network_connection_monitor, 
            daemon=True
        )
        monitor_thread.start()

def main():
    if platform.system() != "Windows":
        print("This script is designed for Windows systems.")
        return

    tracker = BSSIDTracker()
    
    # Current BSSID
    current_bssid = tracker.get_current_wifi_bssid()
    print(f"Current WiFi BSSID: {current_bssid}")

    # Start network monitoring
    tracker.start_monitoring()

    # Keep script running
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()
