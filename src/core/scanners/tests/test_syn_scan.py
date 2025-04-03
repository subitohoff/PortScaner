from ipaddress import IPv4Address
from core.scanners.syn_scanner import SYNScanner
from core.results import ScanResult, PortStatus
from socket import gethostbyname


scanner = SYNScanner()

scanme_ip = gethostbyname("scanme.nmap.org")

res: ScanResult = scanner.scan(IPv4Address(scanme_ip), [22, 25, 113])

assert res.port_status[22] == PortStatus.OPEN
assert res.port_status[25] == PortStatus.FILTERED
assert res.port_status[113] == PortStatus.CLOSED
