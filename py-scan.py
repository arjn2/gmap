import python-nmap

scanner = nmap.PortScanner()
scanner.scan(hosts='192.168.1.0/24', arguments='-sn')
for host in scanner.all_hosts():
    print(f'Host: {host} is {scanner["scan"][host]["status"]["state"]}')