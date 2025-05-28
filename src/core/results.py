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


def default_ping_status():
    return PingStatus(0, False)


@dataclass
class ScanResult:
    port_status: dict[int, PortStatus] = field(default_factory=dict)
    host: IPv4Address | IPv6Address = IPv4Address("0.0.0.0")
    ping_status: PingStatus = field(default_factory=default_ping_status)

    def __str__(self):
        result = f"Host: {self.host}"
        if self.ping_status:
            result += f"\nPing: {'Success' if self.ping_status.success else 'Failed'}"
            if self.ping_status.success:
                result += f" ({self.ping_status.delay_ms}ms)"

        if self.port_status:
            result += "\nPorts:"
            for port, status in self.port_status.items():
                result += f"\n  {port}: {status.name}"

        return result
