from ipaddress import IPv4Address, IPv6Address
from core.results import PingStatus


class Pinger:
    def ping(self, host: IPv4Address | IPv6Address) -> PingStatus:  # pylint: disable=unused-argument
        return PingStatus(0, False)
