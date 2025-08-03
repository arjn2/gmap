# utils/network.py - Enhanced with error handling
import ipaddress

def parse_targets(target_input):
    """Parse IP/range/CIDR to list of IPs with better error handling."""
    try:
        if '/' in target_input:  # CIDR
            network = ipaddress.IPv4Network(target_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif '-' in target_input:  # Range
            start, end = target_input.split('-')
            start_ip = ipaddress.IPv4Address(start.strip())
            end_ip = ipaddress.IPv4Address(end.strip())
            return [str(ipaddress.IPv4Address(i)) 
                    for i in range(int(start_ip), int(end_ip) + 1)]
        else:  # Single IP
            # Validate single IP
            ipaddress.IPv4Address(target_input)
            return [target_input]
    except ipaddress.AddressValueError as e:
        print(f"❌ Invalid IP address format: {target_input}")
        print(f"Error: {e}")
        print("\n💡 Valid examples:")
        print("   Single IP: 192.168.1.1")
        print("   CIDR:      192.168.1.0/24")
        print("   Range:     192.168.1.1-192.168.1.100")
        return []
    except Exception as e:
        print(f"❌ Error parsing target: {e}")
        return []
