# services/device_detector.py - Enhanced device/OS detection

import re

class DeviceDetector:
    def __init__(self):
        self.device_signatures = self._load_signatures()
    
    def _load_signatures(self):
        """Load device/OS signatures database."""
        return {
            'network_devices': {
                'cisco': ['Cisco', 'IOS', 'NXOS', 'cisco'],
                'juniper': ['Juniper', 'JUNOS'],
                'mikrotik': ['MikroTik', 'RouterOS'],
                'ubiquiti': ['Ubiquiti', 'EdgeOS'],
                'netgear': ['NETGEAR', 'ReadyNAS'],
                'linksys': ['Linksys'],
                'tplink': ['TP-LINK', 'TP-Link']
            },
            'iot_devices': {
                'esp32': ['ESP32', 'Espressif'],
                'arduino': ['Arduino'],
                'raspberry_pi': ['Raspberry Pi', 'raspbian'],
                'nvidia_jetson': ['Jetson', 'tegra'],
                'camera': ['axis', 'hikvision', 'dahua'],
                'printer': ['HP LaserJet', 'Canon', 'Epson', 'Brother']
            },
            'servers': {
                'linux': ['Linux', 'Ubuntu', 'CentOS', 'RedHat', 'Debian'],
                'windows': ['Windows', 'Microsoft-IIS', 'Microsoft-HTTPAPI'],
                'freebsd': ['FreeBSD'],
                'macos': ['Darwin', 'macOS']
            },
            'applications': {
                'scopus': ['Scopus', 'Elsevier'],
                'apache': ['Apache'],
                'nginx': ['nginx'],
                'iis': ['Microsoft-IIS'],
                'tomcat': ['Tomcat']
            }
        }
    
    def detect_device(self, banner, open_ports, ip):
        """Comprehensive device detection."""
        results = {
            'device_type': 'Unknown',
            'os': 'Unknown',
            'vendor': 'Unknown', 
            'confidence': 0
        }
        
        # Banner-based detection
        banner_result = self._analyze_banner(banner)
        
        # Port-based detection  
        port_result = self._analyze_ports(open_ports)
        
        # Combine results
        final_result = self._combine_results(banner_result, port_result)
        
        return final_result
    
    def _analyze_banner(self, banner):
        """Analyze banner for device signatures."""
        if not banner:
            return {'device_type': 'Unknown', 'confidence': 0}
            
        banner_lower = banner.lower()
        
        # Check each category
        for category, devices in self.device_signatures.items():
            for device, signatures in devices.items():
                for signature in signatures:
                    if signature.lower() in banner_lower:
                        return {
                            'device_type': self._get_device_type(category, device),
                            'os': self._get_os(device, banner),
                            'vendor': device.title(),
                            'confidence': 90
                        }
        
        return {'device_type': 'Unknown', 'confidence': 0}
    
    def _analyze_ports(self, ports):
        """Analyze port patterns for device identification."""
        if not ports:
            return {'device_type': 'Unknown', 'confidence': 0}
            
        port_patterns = {
            'router': [22, 23, 80, 443, 161],  # SSH, Telnet, HTTP, HTTPS, SNMP
            'printer': [631, 9100, 515],       # IPP, JetDirect, LPD
            'camera': [80, 554, 8080],         # HTTP, RTSP, Alt-HTTP
            'iot': [80, 443, 1883, 8883],      # HTTP, HTTPS, MQTT
            'server': [22, 80, 443, 3389, 5432, 3306]  # SSH, HTTP, HTTPS, RDP, PostgreSQL, MySQL
        }
        
        for device_type, pattern_ports in port_patterns.items():
            matches = len(set(ports) & set(pattern_ports))
            if matches >= 2:  # At least 2 matching ports
                return {
                    'device_type': device_type.title(),
                    'confidence': min(matches * 20, 80)  # Max 80% from ports alone
                }
        
        return {'device_type': 'Unknown', 'confidence': 0}
    
    def _combine_results(self, banner_result, port_result):
        """Combine banner and port analysis results."""
        if banner_result['confidence'] > port_result['confidence']:
            return banner_result
        elif port_result['confidence'] > 0:
            return port_result
        else:
            return {'device_type': 'Unknown', 'os': 'Unknown', 'vendor': 'Unknown', 'confidence': 0}
    
    def _get_device_type(self, category, device):
        """Map device to type category."""
        type_mapping = {
            'network_devices': 'Network Device',
            'iot_devices': 'IoT Device', 
            'servers': 'Server',
            'applications': 'Application Server'
        }
        return type_mapping.get(category, 'Unknown Device')
    
    def _get_os(self, device, banner):
        """Extract OS information."""
        os_patterns = {
            'linux': ['Linux', 'Ubuntu', 'CentOS', 'Debian'],
            'windows': ['Windows', 'Microsoft'],
            'ios': ['Cisco IOS', 'IOS'],
            'embedded': ['embedded', 'ESP32', 'Arduino']
        }
        
        banner_lower = banner.lower()
        for os_name, patterns in os_patterns.items():
            for pattern in patterns:
                if pattern.lower() in banner_lower:
                    return os_name.upper()
        
        return 'Unknown'

# Usage function
def detect_os_device(banner, open_ports=None, ip=None):
    """Main function called by scanner."""
    detector = DeviceDetector()
    return detector.detect_device(banner, open_ports or [], ip)
