from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from enum import Enum

from core.results import ScanResult


class ScanType(Enum):
    TCP = "TCP"
    SYN = "SYN"
    # XMAS = "XMAS"
    # FIN = "FIN"
    # NULL = "NULL"


class Scanner(ABC):
    @abstractmethod
    def scan(self, host: IPv4Address | IPv6Address, ports: list[int]) -> ScanResult:
        pass
