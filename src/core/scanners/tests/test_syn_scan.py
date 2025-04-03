from ipaddress import IPv4Address
from core.scanners.syn_scanner import SYNScanner
from core.results import ScanResult, PortStatus

scanner = SYNScanner()

res: ScanResult = scanner.scan(IPv4Address("192.168.0.157"), [22])
assert res.port_status[22] == PortStatus.OPEN
