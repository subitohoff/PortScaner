from socket import IPPROTO_TCP, htons
from struct import pack
from dataclasses import dataclass


@dataclass
class IPHeader:
    src_addr: bytes
    dst_addr: bytes
    ihl: int = 5
    version: int = 4
    dscp_ecn: int = 0
    tot_len: int = 0  # kernel will do this
    id: int = 0
    frag_off: int = 0
    ttl: int = 255
    proto: int = IPPROTO_TCP
    check: int = 0  # kernel will also do this

    def get_header(self):
        ihl_ver = (self.version << 4) + self.ihl
        return pack(
            "!BBHHHBBH4s4s",
            ihl_ver,
            self.dscp_ecn,
            self.tot_len,
            self.id,
            self.frag_off,
            self.ttl,
            self.proto,
            self.check,
            self.src_addr,
            self.dst_addr,
        )


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq_num: int = 0
    ack_num: int = 0
    data_off: int = 5  # 4 bit, size of header
    # tcp flags
    tcp_fin: int = 0
    tcp_syn: int = 0
    tcp_rst: int = 0
    tcp_psh: int = 0
    tcp_ack: int = 0
    tcp_urg: int = 0
    tcp_ece: int = 0
    tcp_cwr: int = 0

    window: int = htons(5840)  # maximum allowed window size
    check: int = 0
    urg_ptr: int = 0

    def get_header(self):
        offset_res = self.data_off << 4
        tcp_flags = (
            self.tcp_fin
            + (self.tcp_syn << 1)
            + (self.tcp_rst << 2)
            + (self.tcp_psh << 3)
            + (self.tcp_ack << 4)
            + (self.tcp_urg << 5)
            + (self.tcp_ece << 6)
            + (self.tcp_cwr << 7)
        )
        return pack(
            "!HHLLBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_res,
            tcp_flags,
            self.window,
            self.check,
            self.urg_ptr,
        )
