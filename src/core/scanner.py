from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from core.results import ScanResult


class Scanner(ABC):
    @abstractmethod
    def scan(self, host: IPv4Address | IPv6Address, ports: list[int]) -> ScanResult:
        pass
