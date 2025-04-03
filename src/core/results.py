from dataclasses import dataclass, field
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
    port_status: dict[int, PortStatus] = field(default_factory=dict)
    host: IPv4Address | IPv6Address = IPv4Address("0.0.0.0")
    ping_status: PingStatus = PingStatus(0, False)
