# services/fingerprint.py - Basic OS fingerprinting

def detect_os_device(banner):
    """Simple heuristic OS/device detection from banner."""
    if 'Cisco' in banner:
        return 'Cisco Router'
    elif 'Apache' in banner or 'nginx' in banner:
        return 'Linux Server'
    elif 'Microsoft' in banner:
        return 'Windows Device'
    elif 'OpenSSH' in banner:
        return 'Unix-like System'
    else:
        return 'Unknown Device'

def detect_os_device_simple(banner):
    """Simple heuristic OS/device detection from banner only."""
    result = detect_os_device(banner)
    return f"{result['device_type']} ({result['os']})" if result['confidence'] > 0 else 'Unknown Device'

