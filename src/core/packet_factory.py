from struct import pack, unpack
from socket import IPPROTO_TCP

from core.headers import IPHeader, TCPHeader


class PacketFactory:
    def __init__(self, src_addr: bytes, src_port: int, dst_addr: bytes, dst_port: int):
        self.ip_header = IPHeader(src_addr=src_addr, dst_addr=dst_addr)
        self.tcp_header = TCPHeader(src_port=src_port, dst_port=dst_port)

    def _checksum(self, msg: bytes) -> int:
        if len(msg) % 2 == 1:
            msg += b"\x00"

        s = sum(unpack(f"!{len(msg) // 2}H", msg))

        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)

        return ~s & 0xFFFF

    def _generate_pseudo_header(self, tcp_hdr_len: int, usr_data_len: int) -> bytes:
        src_addr = self.ip_header.src_addr
        dst_addr = self.ip_header.dst_addr
        placeholder = 0
        protocol = IPPROTO_TCP
        length = tcp_hdr_len + usr_data_len
        return pack("!4s4sBBH", src_addr, dst_addr, placeholder, protocol, length)

    def generate_packet(self, msg: bytes = bytes()) -> bytes:
        self.tcp_header.check = 0

        tcp_hdr = self.tcp_header.get_header()
        psh = self._generate_pseudo_header(len(tcp_hdr), len(msg))

        checksum = self._checksum(psh + tcp_hdr + msg)

        self.tcp_header.check = checksum
        tcp_hdr = self.tcp_header.get_header()
        ip_hdr = self.ip_header.get_header()

        return ip_hdr + tcp_hdr + msg
