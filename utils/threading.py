# utils/threading.py - Simple parallelism

import concurrent.futures

def parallel_scan(scanner, targets, ports, max_workers=50):
    """Parallel scanning of targets."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scanner.scan_target, ip, ports): ip 
                        for ip in targets}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            results[ip] = future.result()
    return results
