# utils/network.py - Network utilities

import ipaddress

def parse_targets(target_input):
    """Parse IP/range/CIDR to list of IPs."""
    if '/' in target_input:  # CIDR
        network = ipaddress.IPv4Network(target_input)
        return [str(ip) for ip in network.hosts()]
    elif '-' in target_input:  # Range
        start, end = target_input.split('-')
        return [str(ipaddress.IPv4Address(i)) 
                for i in range(int(ipaddress.IPv4Address(start)), 
                               int(ipaddress.IPv4Address(end)) + 1)]
    else:  # Single IP
        return [target_input]
