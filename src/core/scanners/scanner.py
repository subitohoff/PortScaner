from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from enum import Enum
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, error as socket_error
from random import randint
from errno import EADDRINUSE

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

    def get_self_ip(self) -> str:
        s = socket(AF_INET, SOCK_DGRAM)
        s.settimeout(0)
        try:
            # does not have be reachable
            s.connect(("10.254.254.254", 1))
            ip = s.getsockname()[0]
        except socket_error:
            ip = "127.0.0.1"
        finally:
            s.close()

        return ip

    def get_free_port(self, ip_addr: str) -> int:
        port: int

        while True:
            # ephemeral ports are from 49152 to 65535
            port = randint(49152, 65535)
            s = socket(AF_INET, SOCK_STREAM)

            try:
                s.bind((ip_addr, port))
            except socket_error as e:
                if e.errno == EADDRINUSE:
                    continue
                return -1

            s.close()
            return port
