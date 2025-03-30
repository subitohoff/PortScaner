from ipaddress import IPv4Address, IPv6Address

from core.scanners.scanner import Scanner
from core.results import ScanResult, PortStatus


class TCPScanner(Scanner):
    # pylint: disable=duplicate-code
    def scan(self, host: IPv4Address | IPv6Address, ports: list[int]) -> ScanResult:
        # do some actual work
        port_status = {}
        for port in ports:
            port_status[port] = PortStatus.CLOSED

        res = ScanResult(port_status, host)
        return res
