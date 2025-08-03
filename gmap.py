# gmap.py - Main scanner entry point

from core.scanner import Scanner
from core.discovery import ping_host
from core.results import format_results, print_results
from utils.network import parse_targets
from utils.threading import parallel_scan

def main():
    target_input = input("Enter target (IP/CIDR/range): ")
    targets = parse_targets(target_input)
    ports = range(1, 1025)  # Default common ports
    
    live_targets = [ip for ip in targets if ping_host(ip)]
    print(f"Live targets: {len(live_targets)}")
    
    scanner = Scanner(live_targets, ports)
    scan_results = parallel_scan(scanner, live_targets, ports)
    
    formatted = format_results(scan_results)
    print_results(formatted)

if __name__ == "__main__":
    main()
