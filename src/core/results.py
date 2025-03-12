from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv6Address


class PortStatus(Enum):
    OPEN = 1
    CLOSED = 2
    FILTERED = 4


@dataclass
class PingStatus:
    delay_ms: int
    success: bool


@dataclass
class ScanResult:
    port_status: dict[int, PortStatus]
    host: IPv4Address | IPv6Address
    ping_status: PingStatus
