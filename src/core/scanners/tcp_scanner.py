from ipaddress import IPv4Address, IPv6Address

from core.scanners.scanner import Scanner
from core.results import ScanResult, PortStatus
import socket


class TCPScanner(Scanner):
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def scan(self, host: IPv4Address | IPv6Address, ports: list[int]) -> ScanResult:
        port_status = {}

        # dla 4 i 6 zeby dzialalo to jaka
        if isinstance(host, IPv4Address):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6

        for port in ports:
            try:
                print("asdfffffffffff")
                sock = socket.socket(family, socket.SOCK_STREAM)

                sock.settimeout(self.timeout)

                result = sock.connect_ex((str(host), port))
                print("asdassd")
                print(result)
                print("ruskidubger")
                if result == 0:
                    # wedlug intenetow connectex 0 to ze jest open idk will see
                    port_status[port] = PortStatus.OPEN
                else:
                    port_status[port] = PortStatus.CLOSED

                sock.close()

            except socket.timeout:
                port_status[port] = PortStatus.FILTERED
            except socket.error:
                port_status[port] = PortStatus.CLOSED
            except Exception:
                port_status[port] = PortStatus.CLOSED

        res = ScanResult(port_status, host)
        return res
