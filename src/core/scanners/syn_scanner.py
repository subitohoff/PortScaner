from ipaddress import IPv4Address, IPv6Address
from random import randint
from struct import unpack
import socket

from core.scanners.scanner import Scanner
from core.packet_factory import PacketFactory
from core.headers import unpack_headers, TCPHeader, IPHeader, IP_HDR_LEN
from core.results import ScanResult, PortStatus


class SYNScanner(Scanner):
    ICMP_RES_FILTERED = 1
    ICMP_RES_ERROR = 2
    ICMP_RES_OK = 0

    ICMP_UNREACHABLE = 3

    def __init__(self, timeout: int = 10, retires: int = 2):
        self.timeout = timeout
        self.retries = retires
        self.src_ip = self.get_self_ip()

    def is_packet_for_us(
        self, tcp_hdr: TCPHeader, src_port: int, dst_port: int
    ) -> bool:
        if tcp_hdr.src_port != dst_port or tcp_hdr.dst_port != src_port:
            return False

        return True

    def is_packet_syn_ack(self, tcp_hdr: TCPHeader, seq: int) -> bool:
        return (
            tcp_hdr.tcp_syn == 1 and tcp_hdr.tcp_ack == 1 and tcp_hdr.ack_num == seq + 1
        )

    def icmp_error(self, packet: bytes) -> int:
        ip_hdr = IPHeader.from_bytes(packet[:IP_HDR_LEN])

        if not ip_hdr.proto == socket.IPPROTO_ICMP:
            return self.ICMP_RES_OK

        icmp_type, icmp_code = unpack("!BB", packet[IP_HDR_LEN : IP_HDR_LEN + 2])

        if icmp_type != self.ICMP_UNREACHABLE:
            return self.ICMP_RES_ERROR

        icmp_filtered_codes = {1, 2, 3, 9, 10, 13}
        if icmp_code in icmp_filtered_codes:
            return self.ICMP_RES_FILTERED

        return self.ICMP_RES_ERROR

    # returns if it was success (or got timeout)
    def try_send_syn(
        self,
        src_port: int,
        dst_ip_port: tuple[str, int],
        sock: socket.socket,
        pf: PacketFactory,
    ) -> PortStatus:
        pf.tcp_header.tcp_syn = 1
        seq = randint(100, 1_000_000_000)
        pf.tcp_header.seq_num = seq

        out_packet = pf.generate_packet()

        sock.settimeout(self.timeout)

        i = 0
        old_i = -1
        while i < self.retries:
            if i != old_i:
                print("Sending SYN")
                sock.sendto(out_packet, (dst_ip_port[0], 0))
                old_i = i
            try:
                in_packet, in_addr = sock.recvfrom(65535)
            except socket.error:
                # no response
                print("No response")
                i += 1
                continue

            # idk how would that happen but ok
            if in_addr[0] != self.src_ip:
                print("Wrong response src ip")
                continue

            icmp_res = self.icmp_error(in_packet)

            if icmp_res == self.ICMP_RES_FILTERED:
                return PortStatus.FILTERED

            if icmp_res == self.ICMP_RES_ERROR:
                return PortStatus.CLOSED

            _, tcp_hdr = unpack_headers(in_packet)

            if not self.is_packet_for_us(tcp_hdr, src_port, dst_ip_port[1]):
                print("Packet for another port")
                continue

            if not self.is_packet_syn_ack(tcp_hdr, seq):
                print("Response different than SYN/ACK")
                return PortStatus.CLOSED

            print("Received SYN/ACK")
            return PortStatus.OPEN

        # no response after retransmissions
        return PortStatus.FILTERED

    # pylint: disable=duplicate-code
    def scan(self, host: IPv4Address | IPv6Address, ports: list[int]) -> ScanResult:
        # do some actual work
        port_status: dict[int, PortStatus] = {}

        src_addr = socket.inet_aton(self.src_ip)
        dst_addr = socket.inet_aton(str(host))

        src_port = self.get_free_port(self.src_ip)

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        for port in ports:
            sock.bind((self.src_ip, src_port))
            pf = PacketFactory(src_addr, src_port, dst_addr, port)

            # send SYN
            status = self.try_send_syn(src_port, (str(host), port), sock, pf)
            pf.tcp_header.tcp_syn = 0
            pf.tcp_header.seq_num = 0

            if status != PortStatus.OPEN:
                port_status[port] = status
                continue

            # send RST
            pf.tcp_header.tcp_rst = 1
            out_packet = pf.generate_packet()
            print("Sending RST")
            sock.sendto(out_packet, (str(host), 0))

            port_status[port] = PortStatus.OPEN

        sock.close()
        res = ScanResult(port_status, host)
        return res
