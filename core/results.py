# core/results.py - Formats and prints results

def format_results(scan_results):
    """Format scan results with port/service/OS."""
    output = []
    for ip, data in scan_results.items():
        output.append(f"IP: {ip} ({data['os_device']})")
        for result in data['ports']:
            if result['status'] == 'open':
                output.append(
                    f"  Port {result['port']}: {result['status']} "
                    f"- Service: {result['service']} "
                    f"- OS/Device: {result['os_device']}"
                )
    return '\n'.join(output)

def print_results(results):
    """Print formatted results."""
    print(results)
