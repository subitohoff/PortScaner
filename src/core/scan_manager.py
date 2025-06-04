from datetime import timedelta, datetime
from ipaddress import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)
import asyncio

from core.scanners.scanner import ScanType, Scanner
from core.scanners.syn_scanner import SYNScanner
from core.scanners.tcp_scanner import TCPScanner
from core.results import ScanResult
from core.pinger import Pinger


class ScanManager:
    def __init__(
        self, scan_type: ScanType = ScanType.TCP, do_ping: bool = True, threads: int = 1
    ):
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
            if 0 < port < 65536:
                continue
            raise ValueError("Wrong port number")

        self.target_ports = ports

    def set_target_port_range(self, lower_bound: int, upper_bound: int):
        if not 0 < lower_bound < 65536 or not 0 < upper_bound < 65536:
            raise ValueError("Wrong port range")

        if lower_bound > upper_bound:
            lower_bound, upper_bound = upper_bound, lower_bound

        self.target_ports = list(range(lower_bound, upper_bound + 1))

    def _create_scanner(self) -> Scanner:
        if self.scan_type == ScanType.TCP:
            return TCPScanner()
        if self.scan_type == ScanType.SYN:
            return SYNScanner()

        raise ValueError(f"Unknown scan type: {self.scan_type}")

    def _scan_single_threaded(self):
        scanner = self._create_scanner()
        pinger = Pinger()
        for host in self.target_hosts:
            res = ScanResult(host=host)
            if self.ping:
                res.ping_status = pinger.ping(host)
                res.ping_enabled = True
            if (not self.ping) or res.ping_status.success:
                port_result = scanner.scan(host, self.target_ports)
                res.port_status = port_result.port_status
            self.results.append(res)

    async def _scanner_thread(
        self, hosts: list[IPv4Address | IPv6Address], ports: list[int]
    ) -> list[ScanResult]:
        scanner = self._create_scanner()
        pinger = Pinger()
        results: list[ScanResult] = []
        for host in hosts:
            res = ScanResult(host=host)
            if self.ping:
                res.ping_status = pinger.ping(host)
                res.ping_enabled = True
            if (not self.ping) or res.ping_status.success:
                port_result = scanner.scan(host, ports)
                res.port_status = port_result.port_status
            results.append(res)
        return results

    def _chunkify(self, lst: list, chunks: int) -> list[list]:
        return [lst[i::chunks] for i in range(chunks)]

    async def _scan_multi_threaded(self):
        hosts_divided = self._chunkify(self.target_hosts, self.threads)
        tasks: list[asyncio.Task[list[ScanResult]]] = []

        for i in range(self.threads):
            task = asyncio.create_task(
                self._scanner_thread(hosts_divided[i], self.target_ports)
            )
            tasks.append(task)

        for task in tasks:
            result = await task
            self.results += result

    def scan_all(self):
        start_time = datetime.now()

        if self.threads == 1:
            self._scan_single_threaded()
        elif self.threads > 1:
            asyncio.run(self._scan_multi_threaded())

        stop_time = datetime.now()
        self.scan_time = stop_time - start_time
