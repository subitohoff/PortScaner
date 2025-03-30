from datetime import timedelta
from ipaddress import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)
import asyncio

from core.scanner import ScanType, Scanner
from core.results import ScanResult


class ScanManager:
    def __init__(self, scan_type: ScanType = ScanType.TCP, do_ping: bool = True, threads: int = 1):
        self.results: list[ScanResult] = []
        self.scan_time: timedelta = timedelta(0)

        self.target_hosts: list[IPv4Address | IPv6Address] = []
        self.target_ports: list[int] = []
        self.scan_type = scan_type
        self.ping = do_ping
        self.threads = threads

    def get_results(self) -> list[ScanResult]:
        return self.results

    def get_scan_time(self) -> timedelta:
        return self.scan_time

    def add_target_host(self, ipaddress: IPv4Address | IPv6Address):
        self.target_hosts.append(ipaddress)

    def add_target_network(self, ipnetwork: IPv4Network | IPv6Network):
        self.target_hosts += ipnetwork.hosts()

    def set_target_ports(self, ports: list[int]):
        for port in ports:
            if port > 0 and port < 65536:
                continue
            raise ValueError("Wrong port number")
        
        self.target_ports = ports

    def set_target_port_range(self, lower_bound: int, upper_bound: int):
        if (lower_bound < 1 or lower_bound > 65535 or 
            upper_bound < 1 or upper_bound > 65535):
            raise ValueError("Wrong port range")
        
        if lower_bound > upper_bound:
            lower_bound, upper_bound = upper_bound, lower_bound

        self.target_ports = [] + range(lower_bound, upper_bound + 1)

    def scan_single_threaded(self):
        ...

    async def scan_multi_threaded(self):
        ...

    def scan_all(self):
        if self.threads == 1:
            self.scan_single_threaded()
        elif self.threads > 1:
            asyncio.run(self.scan_multi_threaded())
    

        